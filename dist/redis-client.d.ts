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
import type { CircuitBreakerSnapshot, EventSink, RedisOptions, Result, SecurityError } from './types.js';
export declare class RedisClient {
    private readonly client;
    private readonly keyPrefix;
    private readonly commandTimeoutMs;
    private readonly failureThreshold;
    private readonly failureWindowMs;
    private readonly resetTtlMs;
    private readonly halfOpenSuccesses;
    private readonly eventSink;
    /** Failures within `failureWindowMs`. */
    private failureDeltas;
    /** Consecutive successes observed while HALF_OPEN. */
    private halfOpenSuccessCount;
    /** State machine. */
    private state;
    private openedAt;
    private lastFailureAt;
    /** One-shot subscription for state reporting. */
    private lastEmittedState;
    /** SHA1 cache for loaded scripts -> avoids re-LOAD churn. */
    private readonly shaCache;
    /** Tracks ongoing scheduling of the OPEN->HALF_OPEN timer. */
    private resetTimer;
    constructor(opts: RedisOptions, eventSink: EventSink | null);
    /** Returns the global key prefix (already namespace-safe). */
    getKeyPrefix(): string;
    /** Compose a namespaced key. */
    key(suffix: string): string;
    snapshot(): CircuitBreakerSnapshot;
    /**
     * Evaluates a Lua script by SHA1, falling back to `EVAL` (body) if Redis
     * reports `NOSCRIPT` (e.g. after FLUSHALL or cluster takeover). Wraps the
     * entire call in a per-call deadline and the circuit breaker.
     *
     * Returns a `Result`. NEVER throws into the request path.
     */
    evalsha(script: string, keys: ReadonlyArray<string>, args: ReadonlyArray<string | number>): Promise<Result<unknown, SecurityError>>;
    /** Disconnects the underlying connection. Idempotent. */
    close(): void;
    private mayAttempt;
    private transitionTo;
    private emitStateTransition;
    private recordSuccess;
    private recordFailure;
    private withDeadline;
    private evalFallback;
    private emitEvent;
}
//# sourceMappingURL=redis-client.d.ts.map