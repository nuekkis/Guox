/**
 * @guox / modules / hmac-guard.ts — Module 2
 *
 * Request-integrity & replay-attack prevention via HMAC-SHA256 signing.
 * Designed for sensitive endpoints (webhooks, financial transactions) but
 * safely *skippable* on unsigned routes via the `signedRoutes` glob list.
 *
 * What this module guarantees:
 *   - Rejects stale replays: |serverNow - X-Timestamp| > maxDriftMs -> 401.
 *   - Rejects replayed nonces: the nonce is set in Redis with NX semantics
 *     *atomically* (Lua), preventing the TOCTOU race where two concurrent
 *     requests with the same nonce would both pass. TTL = drift window * 1.5.
 *     On breaker OPEN, falls back to an in-memory bounded LRU nonce set.
 *   - Cryptographically reconfirms the signature using a structured
 *     StringToSign:
 *         Verb + "\n" + Path + "\n" + X-Timestamp + "\n" + X-Nonce + "\n" + RawBody
 *     recombined and HMAC-SHA256'd under the per-key pre-shared secret.
 *   - Comparison is constant-time via `crypto.timingSafeEqual` (length-equal
 *     short-circuit always equal-cost since the prefix length comparison
 *     itself does not reveal *which* side mismatched).
 *   - Returns a typed `Result`. Never throws.
 */
import type { HmacOptions, RequestContext, Result, SecurityError } from '../types.js';
import type { RedisClient } from '../redis-client.js';
export interface HmacDecision {
    /** true if request should proceed. */
    readonly valid: boolean;
    readonly rejectKind: HmacRejectKind | null;
    /** Key id used (for audit) or null if not present. */
    readonly keyId: string | null;
}
export type HmacRejectKind = 'missing_signature' | 'missing_key_id' | 'missing_timestamp' | 'missing_nonce' | 'timestamp_drift' | 'replay_detected' | 'unknown_key' | 'signature_invalid' | 'unsigned_route' | 'malformed_timestamp';
export declare class HmacGuard {
    private readonly redis;
    private readonly config;
    private readonly compiledSigned;
    private readonly fallbackNonces;
    constructor(redis: RedisClient, opts: HmacOptions);
    /** Returns true iff the route's `${method} ${path}` matches a signed pattern,
     *  or if all routes are signed (empty `signedRoutes`). */
    private isSignedRoute;
    /**
     * Verifies the request integrity. Returns a `Result<HmacDecision>`.
     * The orchestrator maps non-OK cases to HTTP 401/403 with a specific
     * `rejectKind` for telemetry.
     */
    verify(ctx: RequestContext): Promise<Result<HmacDecision, SecurityError>>;
    /** Maps a non-OK reject to a SecurityError (used by the orchestrator). */
    static rejectKindToError(kind: HmacRejectKind, message: string, ctx: RequestContext): SecurityError;
}
//# sourceMappingURL=hmac-guard.d.ts.map