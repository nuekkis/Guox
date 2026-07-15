"use strict";
/**
 * @guox / guox.ts — main orchestrator
 *
 * Composes every module under one cohesive `Guox` instance.
 *
 * Responsibilities:
 *   - wire the Redis client + circuit breaker once at startup,
 *   - bootstrap per-request `RequestContext`s from a framework adapter,
 *   - run modules in the cheapest-filter-first order,
 *   - translate `Result<>` rejections into framework-neutral HTTP responses
 *     (status + JSON body) + the security audit emission,
 *   - expose the same middleware as both an Express function and a Fastify
 *     hook (`guox.express()`, `guox.fastify()`).
 *
 * The orchestrator is deliberately *not* coupled to Express or Fastify types
 * at the core; it speaks the adapter-agnostic `AdapterRequest/Response`. Each
 * framework adapter (see `adapters/express.ts`, `adapters/fastify.ts`) is a
 * ~30 line translation shim. This guarantees the same identical behaviour
 * regardless of which server the integrator is on.
 *
 * Async tail: the orchestrator's `run()` is `Promise<NextOutcome>`; framework
 * adapters `await` it. The two outcomes are:
 *   - `'continue'` — call the framework's `next()` to proceed to user code.
 *   - `'responded'` — the middleware already wrote the response (via the
 *     `AdapterResponse` interface) and the framework must NOT call `next()`.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.err = exports.ok = exports.Guox = void 0;
const types_js_1 = require("./types.js");
Object.defineProperty(exports, "err", { enumerable: true, get: function () { return types_js_1.err; } });
Object.defineProperty(exports, "ok", { enumerable: true, get: function () { return types_js_1.ok; } });
const redis_client_js_1 = require("./redis-client.js");
const events_js_1 = require("./events.js");
const context_js_1 = require("./context.js");
const util_js_1 = require("./util.js");
const sanitizer_js_1 = require("./modules/sanitizer.js");
const rate_limiter_js_1 = require("./modules/rate-limiter.js");
const ip_reputation_js_1 = require("./modules/ip-reputation.js");
const ja4_bridge_js_1 = require("./modules/ja4-bridge.js");
const hmac_guard_js_1 = require("./modules/hmac-guard.js");
const session_shield_js_1 = require("./modules/session-shield.js");
const schema_drift_js_1 = require("./modules/schema-drift.js");
class Guox {
    redis;
    bus;
    sanitizer;
    ipReputation;
    ja4;
    hmac;
    sessionShield;
    rateLimiter;
    schemaDrift;
    cpuSampler;
    disabled;
    options;
    constructor(opts) {
        this.options = {
            trustProxyHops: opts.trustProxyHops ?? 1,
            rateLimit: opts.rateLimit,
            hmac: opts.hmac,
            sessionShield: opts.sessionShield,
            sanitizer: opts.sanitizer,
            ja4: opts.ja4,
            ipReputation: opts.ipReputation,
            schemaDrift: opts.schemaDrift,
        };
        this.disabled = new Set(opts.disabled ?? []);
        this.bus = new events_js_1.SecurityEventBus(opts.onEvent);
        this.redis = new redis_client_js_1.RedisClient(opts.redis ?? { url: 'redis://localhost:6379' }, this.bus.emit.bind(this.bus));
        // Build modules conditionally.
        this.sanitizer = this.disabled.has('sanitizer')
            ? new sanitizer_js_1.Sanitizer(undefined) /* no-op */
            : new sanitizer_js_1.Sanitizer(opts.sanitizer);
        this.ipReputation = this.disabled.has('ipReputation')
            ? undefined
            : new ip_reputation_js_1.IpReputation(this.redis, opts.ipReputation);
        this.ja4 = this.disabled.has('ja4')
            ? undefined
            : new ja4_bridge_js_1.Ja4Bridge(opts.ja4);
        if (this.ja4 && opts.ja4?.excludeRoutes) {
            // bridge already accepts `excludeRoutes`; nothing further.
        }
        this.hmac = this.disabled.has('hmac')
            ? undefined
            : opts.hmac
                ? new hmac_guard_js_1.HmacGuard(this.redis, opts.hmac)
                : undefined;
        this.sessionShield = this.disabled.has('sessionShield')
            ? undefined
            : opts.sessionShield
                ? new session_shield_js_1.SessionShield(this.redis, opts.sessionShield)
                : undefined;
        if (!this.disabled.has('rateLimit')) {
            const cpuSampler = opts.rateLimit?.adaptive
                ? new util_js_1.CpuLoadSampler()
                : undefined;
            this.cpuSampler = cpuSampler;
            this.rateLimiter = new rate_limiter_js_1.RateLimiter(this.redis, opts.rateLimit, cpuSampler, 0.7);
        }
        else {
            this.rateLimiter = undefined;
        }
        this.schemaDrift = this.disabled.has('schemaDrift')
            ? undefined
            : new schema_drift_js_1.SchemaDrift(opts.schemaDrift);
    }
    /** Wire a security event into the bus; public so integrators can emit
     *  their own (e.g. login failures count toward IP reputation). */
    emit(event) {
        this.bus.emit(event);
    }
    /**
     * Runs the full middleware chain against the adapter-projected request.
     * Adapters wrap their native handlers around this.
     */
    async run(req, res, next) {
        let ctx;
        try {
            ctx = (0, context_js_1.buildContext)(req, { trustProxyHops: this.options.trustProxyHops }, this.identityStrategies(), this.options.rateLimit?.resolveIdentity);
        }
        catch (e) {
            this.emitError('circuit_breaker', 'critical', 'failed to build request context: ' + (e instanceof Error ? e.message : String(e)));
            // We can't continue safely — call user next() so their handlers still
            // run (e.g. flood their logs普惠). This is the "blast-shield fail-open"
            // stance documented in the architecture.
            await Promise.resolve(next());
            return 'continue';
        }
        // If a guard has already written the response (responded outcome), this
        // tracks it for short-circuit at the end so we never call `next`.
        let responded = null;
        try {
            // 2) Sanitizer (sync).
            if (!this.disabled.has('sanitizer')) {
                const r = this.sanitizer.sanitize(ctx);
                if (!r.ok) {
                    const evt = this.sanitizer.buildRejectEvent(ctx, r);
                    this.emit(this.fillEvent(evt, ctx));
                    responded = this.respond(res, this.kindToError(r.rejectKind));
                }
            }
            // 3) IP Reputation fast-path (sync).
            if (!responded && this.ipReputation) {
                const dec = this.ipReputation.isBlocked(ctx);
                if (dec.ok && dec.value.blocked) {
                    this.emit(this.fillEvent({
                        kind: 'ip_blocked',
                        severity: 'warn',
                        message: `IP ${ctx.clientIp} is reputation-blocked; ttl=${dec.value.blockExpiresIn}`,
                        clientIp: ctx.clientIp,
                        path: ctx.path,
                        method: ctx.method,
                    }, ctx));
                    responded = this.respond(res, {
                        kind: 'ip_blocked',
                        message: 'client IP is temporarily blocked due to repeated security violations',
                        statusCode: 403,
                        context: { blockExpiresIn: dec.value.blockExpiresIn },
                    });
                }
            }
            // 4) JA4 / TLS fingerprint bridge (sync).
            if (!responded && this.ja4) {
                const r = this.ja4.verify(ctx);
                if (!r.ok) {
                    this.emit(this.fillEvent({
                        kind: 'tls_spoofing',
                        severity: 'warn',
                        message: r.error.message,
                        clientIp: ctx.clientIp,
                        path: ctx.path,
                        method: ctx.method,
                        context: r.error.context,
                    }, ctx));
                    responded = this.respond(res, r.error);
                }
            }
            // 5) HMAC replay guard (async).
            if (!responded && this.hmac) {
                const r = await this.hmac.verify(ctx);
                if (!r.ok) {
                    this.emit(this.fillEvent({
                        kind: r.error.kind === 'replay_detected' ? 'replay_detected'
                            : r.error.kind === 'timestamp_drift' ? 'timestamp_drift'
                                : 'signature_invalid',
                        severity: 'warn',
                        message: r.error.message,
                        clientIp: ctx.clientIp,
                        path: ctx.path,
                        method: ctx.method,
                        context: r.error.context,
                    }, ctx));
                    // Record reputational impact.
                    await this.maybeRecordViolation(ctx, r.error.kind === 'replay_detected'
                        ? 'replay_detected'
                        : r.error.kind === 'timestamp_drift'
                            ? 'timestamp_drift'
                            : 'signature_invalid');
                    responded = this.respond(res, r.error);
                }
            }
            // 6) Session fingerprint shield (async).
            if (!responded && this.sessionShield) {
                const r = await this.sessionShield.verify(ctx);
                if (!r.ok) {
                    this.emit(this.fillEvent({
                        kind: 'session_hijack',
                        severity: 'error',
                        message: r.error.message,
                        clientIp: ctx.clientIp,
                        path: ctx.path,
                        method: ctx.method,
                        context: r.error.context,
                    }, ctx));
                    await this.maybeRecordViolation(ctx, 'session_hijack');
                    responded = this.respond(res, r.error);
                }
            }
            // 7) Cost-based rate limiter (async).
            if (!responded && this.rateLimiter) {
                const r = await this.rateLimiter.decide(ctx, (c) => (0, context_js_1.resolveIdentityOn)(c, this.identityStrategies(), this.options.rateLimit?.resolveIdentity));
                if (r.ok) {
                    this.rateLimiter.writeHeaders(res.setHeader, r.value);
                    if (!r.value.allowed) {
                        this.emit(this.fillEvent({
                            kind: 'rate_limited',
                            severity: 'info',
                            message: `rate limit exhausted (limit=${r.value.limit})`,
                            clientIp: ctx.clientIp,
                            path: ctx.path,
                            method: ctx.method,
                            identity: ctx.identity,
                            context: { retry: r.value.retryAfter, charged: r.value.charged },
                        }, ctx));
                        await this.maybeRecordViolation(ctx, 'rate_limited');
                        responded = this.respond(res, {
                            kind: 'rate_limited',
                            message: `rate limit exhausted; retry after ${r.value.retryAfter}s`,
                            statusCode: 429,
                            context: {
                                limit: r.value.limit,
                                remaining: r.value.remaining,
                                retryAfter: r.value.retryAfter,
                            },
                        });
                    }
                }
                else if (r.error.kind === 'circuit_open') {
                    // Fail-soft already handled in limiter; we *do not* block here.
                    // Emit a critical event (already fires from breaker).
                }
            }
            // 8) Schema drift (sync).
            if (!responded && this.schemaDrift) {
                const r = this.schemaDrift.check(ctx);
                if (!r.valid) {
                    this.emit(this.fillEvent(this.schemaDrift.buildEvent(ctx, r), ctx));
                    if (this.schemaDrift.shouldBlock()) {
                        responded = this.respond(res, {
                            kind: 'schema_drift',
                            message: 'payload does not match expected schema',
                            statusCode: 422,
                            context: { errors: r.errors },
                        });
                    }
                }
            }
        }
        catch (e) {
            // Defensive: should never happen; every module is typed to never throw.
            // If it does, we log + fall through to `next()` so the user's route
            // handler runs (fail-open on a security middleware bug is dramatically
            // preferable to a 100% outage of the application).
            this.emit(this.fillEvent({
                kind: 'circuit_breaker',
                severity: 'critical',
                message: 'uncaught exception in Guox middleware: ' + (e instanceof Error ? e.message : String(e)),
            }, ctx));
        }
        // If a guard already responded, do NOT call next() — the route handler
        // must not run.
        if (responded === 'responded')
            return 'responded';
        await Promise.resolve(next());
        return 'continue';
    }
    /** Public surface for adapters: Express-compatible handler. */
    expressHandler() {
        // The actual projection lives in adapters/express.ts to keep lazy import
        // of @types/express out of the dependent code paths.
        throw new Error('guox.expressHandler: import express adapter from "guox/adapters/express" instead.');
    }
    /**
     * Frees internal resources (the Redis connection). Useful for tests and
     * graceful shutdown.
     */
    close() {
        this.redis.close();
    }
    /* -------- private -------- */
    identityStrategies() {
        return this.options.rateLimit?.identityStrategies ?? ['api_key', 'jwt_sub', 'ip'];
    }
    fillEvent(evt, ctx) {
        const at = evt.at ?? Date.now();
        return {
            kind: evt.kind,
            severity: evt.severity,
            requestId: evt.requestId ?? ctx.requestId,
            at,
            identity: evt.identity ?? ctx.identity,
            clientIp: evt.clientIp ?? ctx.clientIp,
            path: evt.path ?? ctx.path,
            method: evt.method ?? ctx.method,
            message: evt.message,
            context: evt.context,
        };
    }
    async maybeRecordViolation(ctx, kind) {
        if (!this.ipReputation)
            return;
        try {
            await this.ipReputation.recordViolation(ctx, kind);
        }
        catch {
            /* ignore */
        }
    }
    /** Cheap path for ctx-less critical events (e.g. context bootstrap failed). */
    emitError(kind, severity, message) {
        try {
            this.bus.emit({
                kind,
                severity,
                message,
                requestId: 'system',
                at: Date.now(),
            });
        }
        catch {
            /* swallow */
        }
    }
    kindToError(kind) {
        switch (kind) {
            case 'payload_malformed':
                return { kind: 'payload_malformed', message: 'malformed payload', statusCode: 400 };
            case 'payload_too_deep':
                return { kind: 'payload_too_deep', message: 'payload nesting exceeds max depth', statusCode: 413 };
            case 'prototype_pollution':
                return { kind: 'prototype_pollution', message: 'prototype pollution attempt detected', statusCode: 400 };
            case 'payload_oversize':
                return { kind: 'payload_oversize', message: 'payload exceeds size limit', statusCode: 413 };
            default:
                return { kind: 'misconfigured', message: 'unknown sanitizer rejection', statusCode: 500 };
        }
    }
    respond(res, error) {
        // Defensively absorb any adapter quirks. The orchestrator must NEVER
        // propagate a Zuox-side response-writing exception back into user code,
        // because user code would then think it's still their turn to write the
        // response and produce a broken double-write.
        const safeCall = (fn, fallback) => {
            try {
                return fn();
            }
            catch {
                return fallback;
            }
        };
        safeCall(() => res.setStatus(error.statusCode), undefined);
        safeCall(() => res.setHeader('Content-Type', 'application/json'), undefined);
        safeCall(() => res.sendJson({
            error: {
                kind: error.kind,
                message: error.message,
                ...(error.context ? { context: error.context } : {}),
            },
        }), undefined);
        safeCall(() => res.end(), undefined);
        return 'responded';
    }
}
exports.Guox = Guox;
//# sourceMappingURL=guox.js.map