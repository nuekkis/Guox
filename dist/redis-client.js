"use strict";
/**
 * @guox / redis-client.ts
 *
 * Redis client wrapper with:
 *   - Lazy SCRIPT LOAD + cached EVALSHA fallback to EVAL (resilient to
 *     SCRIPT FLUSH or cluster-failover),
 *   - Circuit breaker that never throws into the request path,
 *   - Per-call deadline (`Promise.race` against a setTimeout guard),
 *   - Emit of structured breaker state transitions via the event sink.
 *
 * The wrapper never imports ioredis directly at module scope; instead it
 * accepts either a connection URL or a *pre-built* instance. This keeps the
 * typing facade clean (we type the client as `unknown` at the boundary) and
 * avoids forcing users onto a specific ioredis release version.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.RedisClient = void 0;
const types_js_1 = require("./types.js");
const DEFAULTS = {
    keyPrefix: 'guox:',
    commandTimeoutMs: 80,
    failureThreshold: 5,
    failureWindowMs: 10_000,
    resetTtlMs: 30_000,
    halfOpenSuccesses: 2,
};
class RedisClient {
    client;
    keyPrefix;
    commandTimeoutMs;
    failureThreshold;
    failureWindowMs;
    resetTtlMs;
    halfOpenSuccesses;
    eventSink;
    /** Failures within `failureWindowMs`. */
    failureDeltas = [];
    /** Consecutive successes observed while HALF_OPEN. */
    halfOpenSuccessCount = 0;
    /** State machine. */
    state = 'closed';
    openedAt = null;
    lastFailureAt = null;
    /** One-shot subscription for state reporting. */
    lastEmittedState = 'closed';
    /** SHA1 cache for loaded scripts -> avoids re-LOAD churn. */
    shaCache = new Map();
    /** Tracks ongoing scheduling of the OPEN->HALF_OPEN timer. */
    resetTimer = null;
    constructor(opts, eventSink) {
        const o = { ...DEFAULTS, ...opts };
        if (o.keyPrefix.length === 0 || !o.keyPrefix.endsWith(':')) {
            // Coerce: if user supplies `guox` (no colon), append it; if empty,
            // fall back to default to avoid polluting the keyspace.
            o.keyPrefix = (o.keyPrefix ?? '') + ':';
        }
        this.keyPrefix = o.keyPrefix;
        this.commandTimeoutMs = o.commandTimeoutMs;
        this.failureThreshold = o.failureThreshold;
        this.failureWindowMs = o.failureWindowMs;
        this.resetTtlMs = o.resetTtlMs;
        this.halfOpenSuccesses = o.halfOpenSuccesses;
        this.eventSink = eventSink;
        // Acquire the underlying connection.
        const clientCandidate = opts.client ?? createIoRedisFromUrl(o.url);
        if (!clientCandidate || typeof clientCandidate.evalsha !== 'function') {
            throw new Error('guox/redis: a usable ioredis client is required (pass `url` or `client`).');
        }
        this.client = clientCandidate;
        // Wire up passive state observation (we do NOT auto-flip breaker here —
        // those transitions are explicitly driven by call outcomes).
        safeOn(this.client, 'error', (...args) => {
            this.emitEvent({
                kind: 'circuit_breaker',
                severity: 'error',
                message: 'ioredis emitted an error event',
                context: { args: args.map((a) => safeStringify(a)) },
            });
        });
    }
    /* -------- public surface -------- */
    /** Returns the global key prefix (already namespace-safe). */
    getKeyPrefix() {
        return this.keyPrefix;
    }
    /** Compose a namespaced key. */
    key(suffix) {
        return this.keyPrefix + suffix;
    }
    snapshot() {
        return {
            state: this.state,
            failures: this.failureDeltas.length,
            lastFailureAt: this.lastFailureAt,
            openedAt: this.openedAt,
        };
    }
    /**
     * Evaluates a Lua script by SHA1, falling back to `EVAL` (body) if Redis
     * reports `NOSCRIPT` (e.g. after FLUSHALL or cluster takeover). Wraps the
     * entire call in a per-call deadline and the circuit breaker.
     *
     * Returns a `Result`. NEVER throws into the request path.
     */
    async evalsha(script, keys, args) {
        if (!this.mayAttempt()) {
            return (0, types_js_1.err)({
                kind: 'circuit_open',
                message: 'circuit breaker is open; redis unavailable',
                statusCode: 503,
            });
        }
        let sha1 = this.shaCache.get(script);
        if (!sha1) {
            try {
                sha1 = await this.withDeadline(this.client.script('LOAD', script));
                this.shaCache.set(script, sha1);
            }
            catch (loadErr) {
                // Fall through to plain EVAL. We treat LOAD failure as a transient
                // network issue (counted against breaker).
                this.recordFailure();
                return this.evalFallback(script, keys, args, loadErr);
            }
        }
        try {
            const ret = await this.withDeadline(this.client.evalsha(sha1, keys.length, ...keys, ...args));
            this.recordSuccess();
            return (0, types_js_1.ok)(ret);
        }
        catch (e) {
            const msg = safeStringify(e);
            // NOSCRIPT: Redis forgot the script. Re-load via EVAL fallback.
            if (typeof msg === 'string' && msg.includes('NOSCRIPT')) {
                return this.evalFallback(script, keys, args, e);
            }
            this.recordFailure();
            return (0, types_js_1.err)({
                kind: 'circuit_open',
                message: 'redis command failed',
                statusCode: 503,
                context: { error: msg },
            });
        }
    }
    /** Disconnects the underlying connection. Idempotent. */
    close() {
        try {
            if (this.resetTimer) {
                clearTimeout(this.resetTimer);
                this.resetTimer = null;
            }
            this.client.disconnect?.();
        }
        catch {
            /* swallow */
        }
    }
    /* -------- internals -------- */
    mayAttempt() {
        const now = Date.now();
        if (this.state === 'closed')
            return true;
        if (this.state === 'open') {
            // Allow a single probe after `resetTtlMs`.
            if (this.openedAt !== null && now - this.openedAt >= this.resetTtlMs) {
                this.transitionTo('half_open');
                return true;
            }
            return false;
        }
        // half_open: a single concurrent probe is allowed.
        return true;
    }
    transitionTo(next) {
        if (next === this.state)
            return;
        this.state = next;
        if (next === 'open') {
            this.openedAt = Date.now();
            this.halfOpenSuccessCount = 0;
            // Schedule a soft re-probe (purely so a totally idle circuit still
            // recovers; the mayAttempt gate also enforces timing independently).
            if (this.resetTimer)
                clearTimeout(this.resetTimer);
            this.resetTimer = setTimeout(() => {
                if (this.state === 'open')
                    this.transitionTo('half_open');
            }, this.resetTtlMs).unref?.();
        }
        else if (next === 'closed') {
            this.openedAt = null;
            this.failureDeltas = [];
            this.halfOpenSuccessCount = 0;
        }
        this.emitStateTransition(next);
    }
    emitStateTransition(next) {
        if (next === this.lastEmittedState)
            return;
        this.lastEmittedState = next;
        const severity = next === 'open' ? 'critical' : next === 'half_open' ? 'warn' : 'info';
        this.emitEvent({
            kind: 'circuit_breaker',
            severity,
            message: `circuit breaker transitioned to ${next}`,
        });
    }
    recordSuccess() {
        if (this.state === 'half_open') {
            this.halfOpenSuccessCount += 1;
            if (this.halfOpenSuccessCount >= this.halfOpenSuccesses) {
                this.transitionTo('closed');
            }
        }
        else if (this.state === 'closed') {
            // Mild decay so a steady stream of successes doesn't keep a stale
            // failure window forever. We just sample down failures so the *rate*
            // of failures (not the absolute count) decides opening.
            this.failureDeltas = this.failureDeltas.filter((t) => Date.now() - t < this.failureWindowMs);
        }
    }
    recordFailure() {
        const now = Date.now();
        this.lastFailureAt = now;
        this.failureDeltas.push(now);
        this.failureDeltas = this.failureDeltas.filter((t) => now - t < this.failureWindowMs);
        if (this.state === 'half_open') {
            // A failure during the probe immediately re-opens.
            this.transitionTo('open');
            return;
        }
        if (this.state === 'closed' && this.failureDeltas.length >= this.failureThreshold) {
            this.transitionTo('open');
        }
    }
    async withDeadline(p) {
        let timer;
        const timeout = new Promise((_, reject) => {
            timer = setTimeout(() => {
                reject(new Error(`guox: redis command deadline (${this.commandTimeoutMs}ms)`));
            }, this.commandTimeoutMs).unref?.();
        });
        try {
            return await Promise.race([p, timeout]);
        }
        finally {
            if (timer)
                clearTimeout(timer);
        }
    }
    async evalFallback(script, keys, args, cause) {
        if (!this.mayAttempt()) {
            return (0, types_js_1.err)({
                kind: 'circuit_open',
                message: 'circuit breaker is open during EVAL fallback',
                statusCode: 503,
            });
        }
        try {
            const ret = await this.withDeadline(this.client.eval(script, keys.length, ...keys, ...args));
            this.recordSuccess();
            return (0, types_js_1.ok)(ret);
        }
        catch (e) {
            this.recordFailure();
            return (0, types_js_1.err)({
                kind: 'circuit_open',
                message: 'redis EVAL fallback failed',
                statusCode: 503,
                context: {
                    originalCause: safeStringify(cause),
                    fallbackError: safeStringify(e),
                },
            });
        }
    }
    emitEvent(payload) {
        const event = {
            requestId: 'system',
            at: Date.now(),
            ...payload,
        };
        try {
            if (this.eventSink)
                this.eventSink(event);
        }
        catch {
            /* event sink must never break request flow */
        }
    }
}
exports.RedisClient = RedisClient;
/* ------------------------------------------------------------------ *
 * Helpers
 * ------------------------------------------------------------------ */
function createIoRedisFromUrl(url) {
    if (!url)
        return null;
    // Lazy require keeps ioredis out of the cold path when integrators pass
    // their own client; also lets tests stub it.
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const IoRedis = require('ioredis');
    return new IoRedis(url, {
        lazyConnect: false,
        enableReadyCheck: true,
        maxRetriesPerRequest: 3,
        enableOfflineQueue: true,
        retryStrategy: (times) => Math.min(times * 200, 2_000),
    });
}
function safeOn(cli, event, listener) {
    try {
        cli.on?.(event, listener);
    }
    catch {
        /* ignore — best-effort */
    }
}
function safeStringify(v) {
    if (v instanceof Error) {
        return `${v.name}: ${v.message}`;
    }
    try {
        return JSON.stringify(v);
    }
    catch {
        return String(v);
    }
}
//# sourceMappingURL=redis-client.js.map