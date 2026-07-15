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

import type {
  BreakerState,
  CircuitBreakerSnapshot,
  EventSink,
  RedisOptions,
  Result,
  SecurityError,
} from './types.js';
import { err, ok } from './types.js';

/**
 * Minimal ioredis-shape used internally. We model only the surface we need;
 * ioredis' actual public API is a *superset* of this shape, so projection is
 * safe under structural object typing.
 */
interface IoRedisLike {
  evalsha(sha1: string, numkeys: number, ...args: Array<string | number>): Promise<unknown>;
  eval(script: string, numkeys: number, ...args: Array<string | number>): Promise<unknown>;
  script(operation: 'LOAD', script: string): Promise<string>;
  on(event: string, listener: (...args: unknown[]) => void): unknown;
  status: string;
  disconnect(): void;
}

type AnyRedis = IoRedisLike;

const DEFAULTS = {
  keyPrefix: 'guox:',
  commandTimeoutMs: 80,
  failureThreshold: 5,
  failureWindowMs: 10_000,
  resetTtlMs: 30_000,
  halfOpenSuccesses: 2,
} as const;

export class RedisClient {
  private readonly client: AnyRedis;
  private readonly keyPrefix: string;
  private readonly commandTimeoutMs: number;
  private readonly failureThreshold: number;
  private readonly failureWindowMs: number;
  private readonly resetTtlMs: number;
  private readonly halfOpenSuccesses: number;
  private readonly eventSink: EventSink | null;

  /** Failures within `failureWindowMs`. */
  private failureDeltas: number[] = [];
  /** Consecutive successes observed while HALF_OPEN. */
  private halfOpenSuccessCount = 0;
  /** State machine. */
  private state: BreakerState = 'closed';
  private openedAt: number | null = null;
  private lastFailureAt: number | null = null;
  /** One-shot subscription for state reporting. */
  private lastEmittedState: BreakerState = 'closed';

  /** SHA1 cache for loaded scripts -> avoids re-LOAD churn. */
  private readonly shaCache = new Map<string, string>();

  /** Tracks ongoing scheduling of the OPEN->HALF_OPEN timer. */
  private resetTimer: NodeJS.Timeout | null = null;

  constructor(opts: RedisOptions, eventSink: EventSink | null) {
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
    const clientCandidate =
      (opts.client as AnyRedis | undefined) ?? createIoRedisFromUrl(o.url);
    if (!clientCandidate || typeof clientCandidate.evalsha !== 'function') {
      throw new Error(
        'guox/redis: a usable ioredis client is required (pass `url` or `client`).',
      );
    }
    this.client = clientCandidate;

    // Wire up passive state observation (we do NOT auto-flip breaker here —
    // those transitions are explicitly driven by call outcomes).
    safeOn(this.client, 'error', (...args: unknown[]) => {
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
  getKeyPrefix(): string {
    return this.keyPrefix;
  }

  /** Compose a namespaced key. */
  key(suffix: string): string {
    return this.keyPrefix + suffix;
  }

  snapshot(): CircuitBreakerSnapshot {
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
  async evalsha(
    script: string,
    keys: ReadonlyArray<string>,
    args: ReadonlyArray<string | number>,
  ): Promise<Result<unknown, SecurityError>> {
    if (!this.mayAttempt()) {
      return err({
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
      } catch (loadErr) {
        // Fall through to plain EVAL. We treat LOAD failure as a transient
        // network issue (counted against breaker).
        this.recordFailure();
        return this.evalFallback(script, keys, args, loadErr);
      }
    }

    try {
      const ret = await this.withDeadline(
        this.client.evalsha(
          sha1,
          keys.length,
          ...keys,
          ...args,
        ),
      );
      this.recordSuccess();
      return ok(ret);
    } catch (e) {
      const msg = safeStringify(e);
      // NOSCRIPT: Redis forgot the script. Re-load via EVAL fallback.
      if (typeof msg === 'string' && msg.includes('NOSCRIPT')) {
        return this.evalFallback(script, keys, args, e);
      }
      this.recordFailure();
      return err({
        kind: 'circuit_open',
        message: 'redis command failed',
        statusCode: 503,
        context: { error: msg },
      });
    }
  }

  /** Disconnects the underlying connection. Idempotent. */
  close(): void {
    try {
      if (this.resetTimer) {
        clearTimeout(this.resetTimer);
        this.resetTimer = null;
      }
      this.client.disconnect?.();
    } catch {
      /* swallow */
    }
  }

  /* -------- internals -------- */

  private mayAttempt(): boolean {
    const now = Date.now();
    if (this.state === 'closed') return true;
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

  private transitionTo(next: BreakerState): void {
    if (next === this.state) return;
    this.state = next;
    if (next === 'open') {
      this.openedAt = Date.now();
      this.halfOpenSuccessCount = 0;
      // Schedule a soft re-probe (purely so a totally idle circuit still
      // recovers; the mayAttempt gate also enforces timing independently).
      if (this.resetTimer) clearTimeout(this.resetTimer);
      this.resetTimer = setTimeout(() => {
        if (this.state === 'open') this.transitionTo('half_open');
      }, this.resetTtlMs).unref?.();
    } else if (next === 'closed') {
      this.openedAt = null;
      this.failureDeltas = [];
      this.halfOpenSuccessCount = 0;
    }
    this.emitStateTransition(next);
  }

  private emitStateTransition(next: BreakerState): void {
    if (next === this.lastEmittedState) return;
    this.lastEmittedState = next;
    const severity =
      next === 'open' ? 'critical' : next === 'half_open' ? 'warn' : 'info';
    this.emitEvent({
      kind: 'circuit_breaker',
      severity,
      message: `circuit breaker transitioned to ${next}`,
    });
  }

  private recordSuccess(): void {
    if (this.state === 'half_open') {
      this.halfOpenSuccessCount += 1;
      if (this.halfOpenSuccessCount >= this.halfOpenSuccesses) {
        this.transitionTo('closed');
      }
    } else if (this.state === 'closed') {
      // Mild decay so a steady stream of successes doesn't keep a stale
      // failure window forever. We just sample down failures so the *rate*
      // of failures (not the absolute count) decides opening.
      this.failureDeltas = this.failureDeltas.filter(
        (t) => Date.now() - t < this.failureWindowMs,
      );
    }
  }

  private recordFailure(): void {
    const now = Date.now();
    this.lastFailureAt = now;
    this.failureDeltas.push(now);
    this.failureDeltas = this.failureDeltas.filter(
      (t) => now - t < this.failureWindowMs,
    );
    if (this.state === 'half_open') {
      // A failure during the probe immediately re-opens.
      this.transitionTo('open');
      return;
    }
    if (this.state === 'closed' && this.failureDeltas.length >= this.failureThreshold) {
      this.transitionTo('open');
    }
  }

  private async withDeadline<T>(p: Promise<T>): Promise<T> {
    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        reject(new Error(`guox: redis command deadline (${this.commandTimeoutMs}ms)`));
      }, this.commandTimeoutMs).unref?.();
    });
    try {
      return await Promise.race([p, timeout]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  private async evalFallback(
    script: string,
    keys: ReadonlyArray<string>,
    args: ReadonlyArray<string | number>,
    cause: unknown,
  ): Promise<Result<unknown, SecurityError>> {
    if (!this.mayAttempt()) {
      return err({
        kind: 'circuit_open',
        message: 'circuit breaker is open during EVAL fallback',
        statusCode: 503,
      });
    }
    try {
      const ret = await this.withDeadline(
        this.client.eval(script, keys.length, ...keys, ...args),
      );
      this.recordSuccess();
      return ok(ret);
    } catch (e) {
      this.recordFailure();
      return err({
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

  private emitEvent(
    payload: Omit<
      import('./types.js').SecurityEvent,
      'requestId' | 'at' | 'kind' | 'message'
    > & {
      kind: import('./types.js').SecurityEventKind;
      message: string;
    },
  ): void {
    const event = {
      requestId: 'system',
      at: Date.now(),
      ...payload,
    } as import('./types.js').SecurityEvent;
    try {
      if (this.eventSink) this.eventSink(event);
    } catch {
      /* event sink must never break request flow */
    }
  }
}

/* ------------------------------------------------------------------ *
 * Helpers
 * ------------------------------------------------------------------ */

function createIoRedisFromUrl(url: string | undefined): AnyRedis | null {
  if (!url) return null;
  // Lazy require keeps ioredis out of the cold path when integrators pass
  // their own client; also lets tests stub it.
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const IoRedis = require('ioredis') as {
    new (url: string, opts?: Record<string, unknown>): AnyRedis;
  };
  return new IoRedis(url, {
    lazyConnect: false,
    enableReadyCheck: true,
    maxRetriesPerRequest: 3,
    enableOfflineQueue: true,
    retryStrategy: (times: number) =>
      Math.min(times * 200, 2_000) as unknown as number,
  });
}

function safeOn(
  cli: AnyRedis,
  event: string,
  listener: (...args: unknown[]) => void,
): void {
  try {
    cli.on?.(event, listener);
  } catch {
    /* ignore — best-effort */
  }
}

function safeStringify(v: unknown): string {
  if (v instanceof Error) {
    return `${v.name}: ${v.message}`;
  }
  try {
    return JSON.stringify(v);
  } catch {
    return String(v);
  }
}
