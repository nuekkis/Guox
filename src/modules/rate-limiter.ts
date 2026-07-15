/**
 * @guox / modules / rate-limiter.ts — Module 1
 *
 * Dynamic cost-based rate limiting via an atomic Redis Lua script.
 *
 * Key concepts:
 *   - Each request carries a *cost weight* (configurable per route), not 1.
 *     So `POST /login` (cost 15) drains the credit pool 15x faster than
 *     `GET /health` (cost 1).
 *   - The credit pool is per-identity (api_key > jwt_sub > ip fallback) over
 *     a *rolling* window. We implement a true sliding log, not a fixed bucket,
 *     to avoid both the start-window burst and the long-tail attack.
 *   - All math is done *inside* a Lua script for atomicity — no read/write
 *     gap that a concurrent abuser could exploit between INCR and EXPIRE.
 *   - When Redis is OPEN (breaker open / network down), we transparently fall
 *     back to an in-memory token-bucket per identity (bounded LRU). The
 *     default fail-soft policy is *allow* so we never take the API down by
 *     failing closed, but integrators wanting strictness can flip to *deny*.
 *
 * Adaptive behavior: when the orchestrator supplies a `cpuSampler` that reports
 * a load above `cpuHighWatermark`, the Lua call is run with a tightened
 * `tightenPct` factor (e.g. 70% of allocated credits) — protects the server
 * when *it* is the bottleneck rather than the request count being the threat.
 */

import type {
  CostRule,
  RateLimitDecision,
  RateLimitOptions,
  RequestContext,
  Result,
  SecurityError,
} from '../types.js';
import { err, ok } from '../types.js';
import type { RedisClient } from '../redis-client.js';
import {
  RATE_LIMIT_LUA,
  decodeRateLimitResult,
} from '../lua-scripts.js';
import {
  CpuLoadSampler,
  LruMap,
  MemoryTokenBucket,
  compileGlob,
  nowSec,
} from '../util.js';

const DEFAULTS = {
  windowSeconds: 60,
  credits: 100,
  identityStrategies: ['api_key', 'jwt_sub', 'ip'] as const,
  failSoft: 'allow' as const,
  emitHeaders: true,
  cpuTightenFactor: 0.7,
  adaptive: false,
};

interface CompiledRule {
  match: (subject: string) => boolean;
  readonly cost: number;
  readonly windowSeconds?: number;
  readonly credits?: number;
}

export class RateLimiter {
  private readonly config: {
    windowSeconds: number;
    credits: number;
    rules: ReadonlyArray<CostRule>;
    identityStrategies: ReadonlyArray<string>;
    failSoft: 'allow' | 'deny';
    emitHeaders: boolean;
    cpuTightenFactor: number;
    adaptive: boolean;
  };
  private readonly compiledRules: CompiledRule[];
  /** Fail-soft fallback: per-identity in-memory token buckets. */
  private readonly fallbackBuckets: LruMap<string, MemoryTokenBucket>;
  /** Per-identity current CPU-tightened effectiveCredit cache for fallback. */
  private readonly cpuConcIntervalMs = 1000;
  private lastCpuSampleAt = 0;
  private lastCpuLoad = 0;

  constructor(
    redis: RedisClient,
    opts?: RateLimitOptions,
    private readonly cpuSampler?: CpuLoadSampler,
    private readonly cpuHighWatermark: number = 0.7,
  ) {
    this.config = {
      windowSeconds: opts?.windowSeconds ?? DEFAULTS.windowSeconds,
      credits: opts?.credits ?? DEFAULTS.credits,
      rules: opts?.rules ?? [],
      identityStrategies: opts?.identityStrategies ?? DEFAULTS.identityStrategies,
      failSoft: opts?.failSoft ?? DEFAULTS.failSoft,
      emitHeaders: opts?.emitHeaders ?? true,
      cpuTightenFactor: opts?.cpuTightenFactor ?? DEFAULTS.cpuTightenFactor,
      adaptive: opts?.adaptive ?? DEFAULTS.adaptive,
    };
    this.compiledRules = this.config.rules.map((r) => ({
      match: compileGlob(this.normalizeRoutePattern(r.pattern, r.method)),
      cost: r.cost,
      windowSeconds: r.windowSeconds,
      credits: r.credits,
    }));
    this.fallbackBuckets = new LruMap<string, MemoryTokenBucket>(4096);
    this.redis = redis;
  }

  private readonly redis: RedisClient;

  /**
   * Returns `Some<RateLimitDecision>` (allow / deny) or
   * `Err<circuit_open>` when Redis is unavailable. Callers usually just call
   * `decide()`; the orchestrator handles `Err` via fail-soft.
   *
   * Cost is resolved in priority:
   *   1. explicit `ctx.routeKey` from the integrator (e.g. `POST /login`)
   *   2. Cost rule match on `${method} ${path}`
   *   3. default cost `1`
   */
  async decide(
    ctx: RequestContext,
    resolveIdentity: (ctx: RequestContext) => {
      identity: string;
      strategy: string;
    } | null,
  ): Promise<Result<RateLimitDecision, SecurityError>> {
    const subject = this.subjectFromContext(ctx);
    const rule = this.matchRule(subject);
    const cost = rule?.cost ?? 1;
    const windowSeconds = rule?.windowSeconds ?? this.config.windowSeconds;
    const credits = rule?.credits ?? this.config.credits;

    const id = resolveIdentity(ctx);
    if (!id) {
      // No identity resolvable -> anonymous. Use a dedicated `anon` bucket
      // so anonymous traffic still gets a fair share instead of being
      // unbounded.
      const fallbackBucketKey = 'anon';
      return this.tryRedisOrFallback(
        fallbackBucketKey,
        cost,
        windowSeconds,
        credits,
        ctx,
      );
    }
    const idKey = id.identity;
    return this.tryRedisOrFallback(idKey, cost, windowSeconds, credits, ctx);
  }

  /** Write the response headers from a decision onto the framework response. */
  writeHeaders(
    setHeader: (name: string, value: string | number) => void,
    decision: RateLimitDecision,
  ): void {
    if (!this.config.emitHeaders) return;
    setHeader('X-RateLimit-Limit-Credits', decision.limit);
    setHeader('X-RateLimit-Remaining-Credits', Math.max(0, decision.remaining));
    if (decision.retryAfter > 0) {
      setHeader('Retry-After', decision.retryAfter);
    }
  }

  /* ---------------- private ---------------- */

  private subjectFromContext(ctx: RequestContext): string {
    return (ctx.routeKey ?? ctx.method + ' ' + ctx.path).toLowerCase();
  }

  private normalizeRoutePattern(pattern: string, method?: string): string {
    if (method && !/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s/i.test(pattern)) {
      return (method + ' ' + pattern).toLowerCase();
    }
    return pattern.toLowerCase();
  }

  private matchRule(subject: string): CompiledRule | null {
    for (let i = 0; i < this.compiledRules.length; i++) {
      const r = this.compiledRules[i]!;
      if (r.match(subject)) return r;
    }
    return null;
  }

  private cpuTightenPct(): number {
    if (!this.config.adaptive || !this.cpuSampler) return 100;
    const now = Date.now();
    if (now - this.lastCpuSampleAt > this.cpuConcIntervalMs) {
      this.lastCpuSampleAt = now;
      try {
        this.lastCpuLoad = this.cpuSampler.sample();
      } catch {
        this.lastCpuLoad = 0;
      }
    }
    if (this.lastCpuLoad >= this.cpuHighWatermark) {
      // Tighten to `cpuTightenFactor * 100` percent of original credits.
      return Math.max(10, Math.round(this.config.cpuTightenFactor * 100));
    }
    return 100;
  }

  private async tryRedisOrFallback(
    identity: string,
    cost: number,
    windowSeconds: number,
    credits: number,
    _ctx: RequestContext,
  ): Promise<Result<RateLimitDecision, SecurityError>> {
    const tightenPct = this.cpuTightenPct();
    const effectiveCredits = Math.max(1, Math.floor((credits * tightenPct) / 100));

    // Hot path: Redis Lua via EVALSHA.
    const windowKey = String(windowSeconds);
    const redisKey = this.redis.key('rl:' + windowKey + ':' + identity);
    const reqId = _ctx.requestId;
    const now = nowSec();
    const ttl = windowSeconds + 5;

    const luaRet = await this.redis.evalsha(
      RATE_LIMIT_LUA,
      [redisKey],
      [reqId, cost, windowSeconds, effectiveCredits, now, ttl, tightenPct],
    );

    if (luaRet.ok) {
      const decision = decodeRateLimitResult(luaRet.value);
      return ok(decision);
    }

    // Fail-soft path: use an in-memory token bucket.
    if (this.config.failSoft === 'deny') {
      return err({
        kind: 'circuit_open',
        message: 'rate limiter circuit is open and policy is fail-closed',
        statusCode: 503,
      });
    }
    return ok(this.fallbackDecide(identity, cost, windowSeconds, effectiveCredits));
  }

  private fallbackDecide(
    identity: string,
    cost: number,
    windowSeconds: number,
    credits: number,
  ): RateLimitDecision {
    let bucket = this.fallbackBuckets.get(identity);
    if (!bucket) {
      bucket = new MemoryTokenBucket(credits, credits, windowSeconds);
      this.fallbackBuckets.set(identity, bucket);
    }
    // The memory bucket refills continuously; reflect cost as integer tokens.
    const remaining = bucket.charge(cost);
    if (remaining >= 0) {
      return {
        allowed: true,
        limit: credits,
        remaining: Math.floor(remaining),
        retryAfter: 0,
        charged: cost,
      };
    }
    // Replenish estimate: refillPerSec = credits / windowSec. Wait seconds
    // ≈ (cost - currentTokens) / refillPerSec, floored.
    const refillPerSec = credits / Math.max(1, windowSeconds);
    const currentTokens = bucket.snapshot().tokens;
    const need = cost - currentTokens;
    const retryAfter = Math.max(1, Math.ceil(need / Math.max(0.001, refillPerSec)));
    return {
      allowed: false,
      limit: credits,
      remaining: Math.floor(Math.max(0, currentTokens)),
      retryAfter,
      charged: 0,
    };
  }
}
