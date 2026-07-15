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
import type { AdapterRequest, AdapterResponse, GuoxOptions, Next, Result, SecurityEvent } from './types.js';
import { err, ok } from './types.js';
export type NextOutcome = 'continue' | 'responded';
export declare class Guox {
    private readonly redis;
    private readonly bus;
    private readonly sanitizer;
    private readonly ipReputation?;
    private readonly ja4?;
    private readonly hmac?;
    private readonly sessionShield?;
    private readonly rateLimiter?;
    private readonly schemaDrift?;
    private readonly cpuSampler?;
    private readonly disabled;
    private readonly options;
    constructor(opts: GuoxOptions);
    /** Wire a security event into the bus; public so integrators can emit
     *  their own (e.g. login failures count toward IP reputation). */
    emit(event: SecurityEvent): void;
    /**
     * Runs the full middleware chain against the adapter-projected request.
     * Adapters wrap their native handlers around this.
     */
    run(req: AdapterRequest, res: AdapterResponse, next: Next): Promise<NextOutcome>;
    /** Public surface for adapters: Express-compatible handler. */
    expressHandler(): (req: unknown, res: unknown, next: Next) => Promise<NextOutcome>;
    /**
     * Frees internal resources (the Redis connection). Useful for tests and
     * graceful shutdown.
     */
    close(): void;
    private identityStrategies;
    private fillEvent;
    private maybeRecordViolation;
    /** Cheap path for ctx-less critical events (e.g. context bootstrap failed). */
    private emitError;
    private kindToError;
    private respond;
}
/** Convenience exported `Result` value factories; re-exported from index. */
export { ok, err, type Result };
//# sourceMappingURL=guox.d.ts.map