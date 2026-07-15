"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.RateLimiter = void 0;
const types_js_1 = require("../types.js");
const lua_scripts_js_1 = require("../lua-scripts.js");
const util_js_1 = require("../util.js");
const DEFAULTS = {
    windowSeconds: 60,
    credits: 100,
    identityStrategies: ['api_key', 'jwt_sub', 'ip'],
    failSoft: 'allow',
    emitHeaders: true,
    cpuTightenFactor: 0.7,
    adaptive: false,
};
class RateLimiter {
    cpuSampler;
    cpuHighWatermark;
    config;
    compiledRules;
    /** Fail-soft fallback: per-identity in-memory token buckets. */
    fallbackBuckets;
    /** Per-identity current CPU-tightened effectiveCredit cache for fallback. */
    cpuConcIntervalMs = 1000;
    lastCpuSampleAt = 0;
    lastCpuLoad = 0;
    constructor(redis, opts, cpuSampler, cpuHighWatermark = 0.7) {
        this.cpuSampler = cpuSampler;
        this.cpuHighWatermark = cpuHighWatermark;
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
            match: (0, util_js_1.compileGlob)(this.normalizeRoutePattern(r.pattern, r.method)),
            cost: r.cost,
            windowSeconds: r.windowSeconds,
            credits: r.credits,
        }));
        this.fallbackBuckets = new util_js_1.LruMap(4096);
        this.redis = redis;
    }
    redis;
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
    async decide(ctx, resolveIdentity) {
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
            return this.tryRedisOrFallback(fallbackBucketKey, cost, windowSeconds, credits, ctx);
        }
        const idKey = id.identity;
        return this.tryRedisOrFallback(idKey, cost, windowSeconds, credits, ctx);
    }
    /** Write the response headers from a decision onto the framework response. */
    writeHeaders(setHeader, decision) {
        if (!this.config.emitHeaders)
            return;
        setHeader('X-RateLimit-Limit-Credits', decision.limit);
        setHeader('X-RateLimit-Remaining-Credits', Math.max(0, decision.remaining));
        if (decision.retryAfter > 0) {
            setHeader('Retry-After', decision.retryAfter);
        }
    }
    /* ---------------- private ---------------- */
    subjectFromContext(ctx) {
        return (ctx.routeKey ?? ctx.method + ' ' + ctx.path).toLowerCase();
    }
    normalizeRoutePattern(pattern, method) {
        if (method && !/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s/i.test(pattern)) {
            return (method + ' ' + pattern).toLowerCase();
        }
        return pattern.toLowerCase();
    }
    matchRule(subject) {
        for (let i = 0; i < this.compiledRules.length; i++) {
            const r = this.compiledRules[i];
            if (r.match(subject))
                return r;
        }
        return null;
    }
    cpuTightenPct() {
        if (!this.config.adaptive || !this.cpuSampler)
            return 100;
        const now = Date.now();
        if (now - this.lastCpuSampleAt > this.cpuConcIntervalMs) {
            this.lastCpuSampleAt = now;
            try {
                this.lastCpuLoad = this.cpuSampler.sample();
            }
            catch {
                this.lastCpuLoad = 0;
            }
        }
        if (this.lastCpuLoad >= this.cpuHighWatermark) {
            // Tighten to `cpuTightenFactor * 100` percent of original credits.
            return Math.max(10, Math.round(this.config.cpuTightenFactor * 100));
        }
        return 100;
    }
    async tryRedisOrFallback(identity, cost, windowSeconds, credits, _ctx) {
        const tightenPct = this.cpuTightenPct();
        const effectiveCredits = Math.max(1, Math.floor((credits * tightenPct) / 100));
        // Hot path: Redis Lua via EVALSHA.
        const windowKey = String(windowSeconds);
        const redisKey = this.redis.key('rl:' + windowKey + ':' + identity);
        const reqId = _ctx.requestId;
        const now = (0, util_js_1.nowSec)();
        const ttl = windowSeconds + 5;
        const luaRet = await this.redis.evalsha(lua_scripts_js_1.RATE_LIMIT_LUA, [redisKey], [reqId, cost, windowSeconds, effectiveCredits, now, ttl, tightenPct]);
        if (luaRet.ok) {
            const decision = (0, lua_scripts_js_1.decodeRateLimitResult)(luaRet.value);
            return (0, types_js_1.ok)(decision);
        }
        // Fail-soft path: use an in-memory token bucket.
        if (this.config.failSoft === 'deny') {
            return (0, types_js_1.err)({
                kind: 'circuit_open',
                message: 'rate limiter circuit is open and policy is fail-closed',
                statusCode: 503,
            });
        }
        return (0, types_js_1.ok)(this.fallbackDecide(identity, cost, windowSeconds, effectiveCredits));
    }
    fallbackDecide(identity, cost, windowSeconds, credits) {
        let bucket = this.fallbackBuckets.get(identity);
        if (!bucket) {
            bucket = new util_js_1.MemoryTokenBucket(credits, credits, windowSeconds);
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
exports.RateLimiter = RateLimiter;
//# sourceMappingURL=rate-limiter.js.map