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

import type {
  AdapterRequest,
  AdapterResponse,
  GuoxOptions,
  IdentityResolution,
  Next,
  RateLimitOptions,
  RequestContext,
  Result,
  SecurityError,
  SecurityEvent,
} from './types.js';
import { err, ok } from './types.js';
import { RedisClient } from './redis-client.js';
import { SecurityEventBus } from './events.js';
import { buildContext, resolveIdentityOn } from './context.js';
import { CpuLoadSampler } from './util.js';
import { Sanitizer } from './modules/sanitizer.js';
import { RateLimiter } from './modules/rate-limiter.js';
import { IpReputation } from './modules/ip-reputation.js';
import { Ja4Bridge } from './modules/ja4-bridge.js';
import { HmacGuard } from './modules/hmac-guard.js';
import { SessionShield } from './modules/session-shield.js';
import { SchemaDrift } from './modules/schema-drift.js';

export type NextOutcome = 'continue' | 'responded';

export class Guox {
  private readonly redis: RedisClient;
  private readonly bus: SecurityEventBus;
  private readonly sanitizer: Sanitizer;
  private readonly ipReputation?: IpReputation;
  private readonly ja4?: Ja4Bridge;
  private readonly hmac?: HmacGuard;
  private readonly sessionShield?: SessionShield;
  private readonly rateLimiter?: RateLimiter;
  private readonly schemaDrift?: SchemaDrift;
  private readonly disabled: Set<string>;
  private readonly options: Required<Pick<GuoxOptions, 'trustProxyHops'>> &
    Omit<GuoxOptions, 'redis' | 'trustProxyHops' | 'disabled' | 'onEvent'> & {
      trustProxyHops: number;
    };

  constructor(opts: GuoxOptions) {
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
    this.bus = new SecurityEventBus(opts.onEvent);
    this.redis = new RedisClient(opts.redis ?? { url: 'redis://localhost:6379' }, this.bus.emit.bind(this.bus));

    // Build modules conditionally.
    this.sanitizer = this.disabled.has('sanitizer')
      ? (new Sanitizer(undefined) /* no-op */ as Sanitizer)
      : new Sanitizer(opts.sanitizer);

    this.ipReputation = this.disabled.has('ipReputation')
      ? undefined
      : new IpReputation(this.redis, opts.ipReputation);

    this.ja4 = this.disabled.has('ja4')
      ? undefined
      : new Ja4Bridge(opts.ja4);

    this.hmac = this.disabled.has('hmac')
      ? undefined
      : opts.hmac
        ? new HmacGuard(this.redis, opts.hmac)
        : undefined;

    this.sessionShield = this.disabled.has('sessionShield')
      ? undefined
      : opts.sessionShield
        ? new SessionShield(this.redis, opts.sessionShield)
        : undefined;

    if (!this.disabled.has('rateLimit')) {
      const cpuSampler = opts.rateLimit?.adaptive
        ? new CpuLoadSampler()
        : undefined;
      this.rateLimiter = new RateLimiter(
        this.redis,
        opts.rateLimit,
        cpuSampler,
        0.7, // cpuHighWatermark
      );
    } else {
      this.rateLimiter = undefined;
    }

    this.schemaDrift = this.disabled.has('schemaDrift')
      ? undefined
      : new SchemaDrift(opts.schemaDrift);
  }

  /** Wire a security event into the bus; public so integrators can emit
   *  their own (e.g. login failures count toward IP reputation). */
  emit(event: SecurityEvent): void {
    this.bus.emit(event);
  }

  /**
   * Runs the full middleware chain against the adapter-projected request.
   * Adapters wrap their native handlers around this.
   */
  async run(
    req: AdapterRequest,
    res: AdapterResponse,
    next: Next,
  ): Promise<NextOutcome> {
    let ctx: RequestContext;
    try {
      ctx = buildContext(
        req,
        { trustProxyHops: this.options.trustProxyHops },
        this.identityStrategies(),
        this.options.rateLimit?.resolveIdentity,
      );
    } catch (e) {
      this.emitError(
        'circuit_breaker',
        'critical',
        'failed to build request context: ' + (e instanceof Error ? e.message : String(e)),
      );
      // We can't continue safely — call user next() so their handlers still
      // run (e.g. flood their logs普惠). This is the "blast-shield fail-open"
      // stance documented in the architecture.
      await Promise.resolve(next());
      return 'continue';
    }

    // If a guard has already written the response (responded outcome), this
    // tracks it for short-circuit at the end so we never call `next`.
    let responded: 'responded' | null = null;

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
          await this.maybeRecordViolation(
            ctx,
            r.error.kind === 'replay_detected'
              ? 'replay_detected'
              : r.error.kind === 'timestamp_drift'
                ? 'timestamp_drift'
                : 'signature_invalid',
          );
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
        const r = await this.rateLimiter.decide(ctx, (c) =>
          resolveIdentityOn(
            c,
            this.identityStrategies(),
            this.options.rateLimit?.resolveIdentity,
          ) as IdentityResolution | null,
        );
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
        } else if (r.error.kind === 'circuit_open') {
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
    } catch (e) {
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
    if (responded === 'responded') return 'responded';
    await Promise.resolve(next());
    return 'continue';
  }

  /** Public surface for adapters: Express-compatible handler. */
  expressHandler(): (
    req: unknown,
    res: unknown,
    next: Next,
  ) => Promise<NextOutcome> {
    // The actual projection lives in adapters/express.ts to keep lazy import
    // of @types/express out of the dependent code paths.
    throw new Error(
      'guox.expressHandler: import express adapter from "guox/adapters/express" instead.',
    );
  }

  /**
   * Frees internal resources (the Redis connection). Useful for tests and
   * graceful shutdown.
   */
  close(): void {
    this.redis.close();
  }

  /* -------- private -------- */

  private identityStrategies(): NonNullable<RateLimitOptions['identityStrategies']> {
    return this.options.rateLimit?.identityStrategies ?? ['api_key', 'jwt_sub', 'ip'];
  }

  private fillEvent(
    evt: Omit<SecurityEvent, 'requestId' | 'at'> & { requestId?: string; at?: number },
    ctx: RequestContext,
  ): SecurityEvent {
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

  private async maybeRecordViolation(
    ctx: RequestContext,
    kind: SecurityEvent['kind'],
  ): Promise<void> {
    if (!this.ipReputation) return;
    try {
      await this.ipReputation.recordViolation(ctx, kind);
    } catch {
      /* ignore */
    }
  }

  /** Cheap path for ctx-less critical events (e.g. context bootstrap failed). */
  private emitError(
    kind: SecurityEvent['kind'],
    severity: SecurityEvent['severity'],
    message: string,
  ): void {
    try {
      this.bus.emit({
        kind,
        severity,
        message,
        requestId: 'system',
        at: Date.now(),
      });
    } catch {
      /* swallow */
    }
  }

  private kindToError(
    kind:
      | 'payload_malformed'
      | 'payload_too_deep'
      | 'prototype_pollution'
      | 'payload_oversize'
      | null,
  ): SecurityError {
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

  private respond(res: AdapterResponse, error: SecurityError): 'responded' {
    // Defensively absorb any adapter quirks. The orchestrator must NEVER
    // propagate a Zuox-side response-writing exception back into user code,
    // because user code would then think it's still their turn to write the
    // response and produce a broken double-write.
    const safeCall = <T>(fn: () => T, fallback: T): T => {
      try {
        return fn();
      } catch {
        return fallback;
      }
    };
    safeCall(() => res.setStatus(error.statusCode), undefined as void);
    safeCall(() => res.setHeader('Content-Type', 'application/json'), undefined as void);
    safeCall(
      () =>
        res.sendJson({
          error: {
            kind: error.kind,
            message: error.message,
            ...(error.context ? { context: error.context } : {}),
          },
        }),
      undefined as void,
    );
    safeCall(() => res.end(), undefined as void);
    return 'responded';
  }
}

/** Convenience exported `Result` value factories; re-exported from index. */
export { ok, err, type Result };
