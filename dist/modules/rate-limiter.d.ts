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
import type { RateLimitDecision, RateLimitOptions, RequestContext, Result, SecurityError } from '../types.js';
import type { RedisClient } from '../redis-client.js';
import { CpuLoadSampler } from '../util.js';
export declare class RateLimiter {
    private readonly cpuSampler?;
    private readonly cpuHighWatermark;
    private readonly config;
    private readonly compiledRules;
    /** Fail-soft fallback: per-identity in-memory token buckets. */
    private readonly fallbackBuckets;
    /** Per-identity current CPU-tightened effectiveCredit cache for fallback. */
    private readonly cpuConcIntervalMs;
    private lastCpuSampleAt;
    private lastCpuLoad;
    constructor(redis: RedisClient, opts?: RateLimitOptions, cpuSampler?: CpuLoadSampler | undefined, cpuHighWatermark?: number);
    private readonly redis;
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
    decide(ctx: RequestContext, resolveIdentity: (ctx: RequestContext) => {
        identity: string;
        strategy: string;
    } | null): Promise<Result<RateLimitDecision, SecurityError>>;
    /** Write the response headers from a decision onto the framework response. */
    writeHeaders(setHeader: (name: string, value: string | number) => void, decision: RateLimitDecision): void;
    private subjectFromContext;
    private normalizeRoutePattern;
    private matchRule;
    private cpuTightenPct;
    private tryRedisOrFallback;
    private fallbackDecide;
}
//# sourceMappingURL=rate-limiter.d.ts.map