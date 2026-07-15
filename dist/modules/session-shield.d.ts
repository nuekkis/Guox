/**
 * @guox / modules / session-shield.ts — Module 3
 *
 * Adaptive session hijacking & fingerprint shield. Detects when a valid,
 * non-expired JWT/SessionID is presented from a context that does NOT match
 * the high-entropy fingerprint minted at login.
 *
 * Fingerprint inputs (canonicalized):
 *   - IP subnet:  /24 for IPv4 or /48 for IPv6
 *   - User-Agent: lowercased + collapsed-whitespace
 *   - Accept-Language (if present, normalized lowercased head-tag)
 *   - Sec-CH-UA::Sec-CH-UA-Mobile/Platform fields (if present)
 *
 * These are concatenated with a domain-separated separator and SHA-256'd to a
 * fixed 64-char hex digest. The hash is then either:
 *   - encrypted and embedded as a JWT claim called `fp` (the canonical path
 *     for stateless JWT), or
 *   - stored in Redis as `guox:session:<sessionId> -> {"fp": "<hash>", ...}`
 *     and re-read on every request (canonical path for opaque session IDs).
 *
 * Verification:
 *   - On every middleware invocation we re-compute the hash *from the live
 *     request* and compare it (timing-safe) to the recorded claim.
 *   - Mismatch options:
 *       'block': revoke session in Redis + blacklist the JWT jti, return 401.
 *       'flag':  log a `session_hijack` event but continue (some operators
 *                want this for honeypot analysis).
 */
import type { FingerprintHash, FingerprintShieldOptions, RequestContext, Result, SecurityError, SessionClaims } from '../types.js';
import type { RedisClient } from '../redis-client.js';
export interface SessionShieldDecision {
    readonly ok: boolean;
    /** Refers to claim mismatch (vs presentation missing entirely). */
    readonly reason: 'matched' | 'missing_claims' | 'fingerprint_mismatch' | null;
}
export declare class SessionShield {
    private readonly redis;
    private readonly config;
    constructor(redis: RedisClient, opts: FingerprintShieldOptions);
    /** Public helper: mint a fresh fingerprint hash from a RequestContext.
     *  Useful for login/issue handlers via `encryptFpClaim(fingerprintOf(ctx))`. */
    fingerprintOf(ctx: RequestContext): FingerprintHash;
    /** Convenience wrapper around the integrator's `encryptFpClaim`. */
    encryptFor(ctx: RequestContext): Promise<string | null>;
    /**
     * Verifies the request matches its declared fingerprint. Returns a Result
     * with `ok=true` when the fingerprint matches, or a typed error when not.
     *
     * On mismatch with `onMismatch='block'`, the session is *also* revoked:
     *   - JWT: blacklists `jti` in Redis for the remaining lifetime.
     *   - Session ID: deletes `guox:session:<sessionId>` (best-effort, ignored
     *     if breaker OPEN).
     *
     * The caller is expected to translate the SecurityError to a 401 response.
     */
    verify(ctx: RequestContext): Promise<Result<SessionShieldDecision, SecurityError>>;
    /** External API: explicit session revocation (e.g. logout). */
    revoke(claims: SessionClaims): Promise<void>;
    /** External API: associate a session id with a fresh fingerprint at login.
     *  Storage entry: HASH with `fp` field and identical TTL to upstream TTL. */
    associate(sessionId: string, fpHash: FingerprintHash, ttlSeconds: number): Promise<void>;
    private resolveRecordedFingerprint;
}
//# sourceMappingURL=session-shield.d.ts.map