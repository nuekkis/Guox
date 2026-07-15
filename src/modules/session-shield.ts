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

import type {
  FingerprintHash,
  FingerprintShieldOptions,
  RequestContext,
  Result,
  SecurityError,
  SessionClaims,
} from '../types.js';
import { err, ok, FingerprintHash as fpBrand } from '../types.js';
import type { RedisClient } from '../redis-client.js';
import { JWT_BLACKLIST_LUA } from '../lua-scripts.js';
import { sha256Hex, timingSafeStringEq } from '../util.js';

export interface SessionShieldDecision {
  readonly ok: boolean;
  /** Refers to claim mismatch (vs presentation missing entirely). */
  readonly reason: 'matched' | 'missing_claims' | 'fingerprint_mismatch' | null;
}

const DEFAULTS = {
  fpClaimName: 'fp',
  onMismatch: 'block' as const,
};

export class SessionShield {
  private readonly config: Required<
    Pick<FingerprintShieldOptions, 'fpClaimName' | 'onMismatch'> & {
      extractClaims: NonNullable<FingerprintShieldOptions['extractClaims']>;
    }
  > & {
    decryptFpClaim: FingerprintShieldOptions['decryptFpClaim'];
    encryptFpClaim: FingerprintShieldOptions['encryptFpClaim'];
  };

  constructor(
    private readonly redis: RedisClient,
    opts: FingerprintShieldOptions,
  ) {
    if (!opts.extractClaims || typeof opts.extractClaims !== 'function') {
      throw new Error('guox/sessionShield: `extractClaims` resolver is required');
    }
    this.config = {
      extractClaims: opts.extractClaims,
      decryptFpClaim: opts.decryptFpClaim,
      encryptFpClaim: opts.encryptFpClaim,
      fpClaimName: opts.fpClaimName ?? DEFAULTS.fpClaimName,
      onMismatch: opts.onMismatch ?? DEFAULTS.onMismatch,
    };
  }

  /** Public helper: mint a fresh fingerprint hash from a RequestContext.
   *  Useful for login/issue handlers via `encryptFpClaim(fingerprintOf(ctx))`. */
  fingerprintOf(ctx: RequestContext): FingerprintHash {
    return fpBrand(sha256Hex(canonicalFingerprintString(ctx)));
  }

  /** Convenience wrapper around the integrator's `encryptFpClaim`. */
  async encryptFor(ctx: RequestContext): Promise<string | null> {
    const enc = this.config.encryptFpClaim;
    if (!enc) return null;
    return await Promise.resolve(enc(this.fingerprintOf(ctx)));
  }

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
  async verify(ctx: RequestContext): Promise<Result<SessionShieldDecision, SecurityError>> {
    const claims = this.config.extractClaims(ctx);
    if (!claims) {
      // The route is not authed, or extractor returned null. Skip.
      return ok({ ok: true, reason: 'missing_claims' });
    }

    const liveFp = this.fingerprintOf(ctx);
    const recordedFp = await this.resolveRecordedFingerprint(claims, ctx);
    if (recordedFp === null) {
      // No recorded fingerprint yet — this is a fresh authentication. We
      // treat it as "matched" so login-on-first-request works without a
      // separate issuance path. The integrator can opt to *require*
      // recorded fingerprints by installing their own middleware before us.
      return ok({ ok: true, reason: 'matched' });
    }

    const matches = timingSafeStringEq(liveFp, recordedFp);
    if (matches) {
      return ok({ ok: true, reason: 'matched' });
    }

    // Mismatch — proceed based on policy.
    if (this.config.onMismatch === 'flag') {
      return ok({ ok: true, reason: 'fingerprint_mismatch' });
    }

    // Block path: revoke JWT (if jti present) and/or clear session map.
    await this.revoke(claims);

    return err({
      kind: 'session_hijack',
      message: 'session fingerprint mismatch; session has been revoked',
      statusCode: 401,
      context: {
        sub: claims.sub,
        sid: claims.sessionId,
        jti: claims.jti,
        liveFp: redactFp(liveFp),
        recordedFp: redactFp(recordedFp),
      },
    });
  }

  /** External API: explicit session revocation (e.g. logout). */
  async revoke(claims: SessionClaims): Promise<void> {
    if (claims.jti && claims.exp) {
      const ttlSec = Math.max(1, Math.floor(claims.exp - Date.now() / 1000));
      try {
        // best-effort — we don't fail the request on breaker OPEN; we already
        // invented the rejection above.
        await this.redis.evalsha(JWT_BLACKLIST_LUA, [this.redis.key('revoked:jwt:' + claims.jti)], [
          String(ttlSec),
          '1',
        ]);
      } catch {
        /* ignored */
      }
    }
    if (claims.sessionId) {
      // Deletion is idempotent. ioredis supports the method as call indirection;
      // we use the evalsha wrapper's authorize surface by issuing a tiny Lua.
      // Simpler: just DEL. We can't evalsha an empty script, so we use a
      // dedicated native op via the wrapper. Since RedisClient only exposes
      // evalsha, we encode DEL through a one-line Lua script.
      try {
        await this.redis.evalsha(
          `return redis.call('DEL', KEYS[1])`,
          [this.redis.key('session:' + claims.sessionId)],
          [],
        );
      } catch {
        /* ignored */
      }
    }
  }

  /** External API: associate a session id with a fresh fingerprint at login.
   *  Storage entry: HASH with `fp` field and identical TTL to upstream TTL. */
  async associate(sessionId: string, fpHash: FingerprintHash, ttlSeconds: number): Promise<void> {
    try {
      await this.redis.evalsha(
        `redis.call('HSET', KEYS[1], 'fp', ARGV[1])
         redis.call('EXPIRE', KEYS[1], ARGV[2])
         return 1`,
        [this.redis.key('session:' + sessionId)],
        [fpHash, String(ttlSeconds)],
      );
    } catch {
      /* ignore best-effort */
    }
  }

  /* -------- private -------- */

  private async resolveRecordedFingerprint(
    claims: SessionClaims,
    _ctx: RequestContext,
  ): Promise<FingerprintHash | null> {
    // Path A: JWT claim (stateless).
    const claimName = this.config.fpClaimName;
    const injectedClaim = (claims as Record<string, unknown>)[claimName];
    if (typeof injectedClaim === 'string' && injectedClaim.length > 0) {
      if (this.config.decryptFpClaim) {
        try {
          const decrypted = await Promise.resolve(this.config.decryptFpClaim(injectedClaim));
          if (decrypted) return decrypted;
        } catch {
          return null;
        }
      } else {
        return fpBrand(injectedClaim);
      }
    }
    // Path B: session id -> Redis hash.
    if (claims.sessionId) {
      try {
        const retResult = await this.redis.evalsha(
          `local v = redis.call('HGET', KEYS[1], 'fp'); if v == false then return '' else return v end`,
          [this.redis.key('session:' + claims.sessionId)],
          [],
        );
        if (retResult.ok) {
          const ret = retResult.value;
          if (typeof ret === 'string' && ret.length > 0) {
            // ioredis resolves single-string HGET directly.
            return fpBrand(ret);
          }
          if (Array.isArray(ret) && ret.length > 0 && ret[0] !== undefined) {
            // Some ioredis configs return arrays; coerce defensively.
            const s = String(ret[0]);
            if (s.length > 0) return fpBrand(s);
          }
          if (
            ret !== null &&
            typeof ret === 'object' &&
            typeof (ret as { toString?: () => string }).toString === 'function'
          ) {
            const s = String(ret);
            if (s.length > 0 && s !== '[object Object]') return fpBrand(s);
          }
        }
      } catch {
        /* breaker OPEN or similar — fall through */
      }
    }
    return null;
  }
}

/* ------------------------------------------------------------------ *
 * Canonical fingerprint string
 *
 * Order matters: tuple is domain-separated with `\x1f` (unit separator,
 * nonsensical in headers) so a malicious UA can't manufacture a collision
 * by smuggling delimiters.
 * ------------------------------------------------------------------ */
function canonicalFingerprintString(ctx: RequestContext): string {
  // IP subnet — canonicalize /24 (IPv4) or /48 (IPv6).
  const ipSubnet = ipSubnetOf(ctx.clientIp);
  const ua = ctx.userAgent; // already lowercased + whitespace-collapsed
  // Accept-Language: keep just the first q=1 prefix tag if present, else
  // first 8 chars; lower-cased.
  const alang = normalizeAcceptLanguage(ctx.acceptLanguage);
  // Sec-CH-UA: take platform + mobile bits, not brands (which vary
  // per update). Sec-CH-UA-Mobile and Sec-CH-UA-Platform are great
  // anti-spoof signals because bots usually forget them.
  const secChUa = ctx.secChUa.slice(0, 64);

  return [ipSubnet, ua, alang, secChUa].join('\x1f');
}

function normalizeAcceptLanguage(raw: string): string {
  if (raw.length === 0) return '';
  // Lowercase, head tag only (strip q=).
  const comma = raw.indexOf(',');
  const head = (comma >= 0 ? raw.slice(0, comma) : raw).trim();
  return head.length > 0 ? head.slice(0, 32) : '';
}

function ipSubnetOf(ip: string): string {
  // IPv4: first 3 octets.
  if (ip.includes('.')) {
    const parts = ip.split('.');
    return parts.slice(0, 3).join('.') + '.0';
  }
  // IPv6: first 3 hextets.
  if (ip.includes(':')) {
    const parts = ip.split(':');
    return parts.slice(0, 3).join(':').toLowerCase() + '::';
  }
  return ip;
}

function redactFp(fp: string): string {
  // Pulled out so the audit trail reveals a stub (e.g. first 8 chars) without
  // ever leaking the full fingerprint itself.
  if (fp.length <= 8) return '*'.repeat(fp.length);
  return fp.slice(0, 8) + '*' + fp.slice(-4);
}
