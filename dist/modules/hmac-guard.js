"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.HmacGuard = void 0;
const node_crypto_1 = require("node:crypto");
const types_js_1 = require("../types.js");
const lua_scripts_js_1 = require("../lua-scripts.js");
const util_js_1 = require("../util.js");
const DEFAULTS = {
    keyIdHeader: 'X-Key-Id',
    signatureHeader: 'X-Signature',
    timestampHeader: 'X-Timestamp',
    nonceHeader: 'X-Nonce',
    maxDriftMs: 5_000,
    signatureEncoding: 'hex',
};
class HmacGuard {
    redis;
    config;
    compiledSigned;
    fallbackNonces;
    constructor(redis, opts) {
        this.redis = redis;
        this.config = {
            keyIdHeader: opts.keyIdHeader ?? DEFAULTS.keyIdHeader,
            signatureHeader: opts.signatureHeader ?? DEFAULTS.signatureHeader,
            timestampHeader: opts.timestampHeader ?? DEFAULTS.timestampHeader,
            nonceHeader: opts.nonceHeader ?? DEFAULTS.nonceHeader,
            maxDriftMs: opts.maxDriftMs ?? DEFAULTS.maxDriftMs,
            nonceTtlMs: opts.nonceTtlMs ?? Math.ceil((opts.maxDriftMs ?? DEFAULTS.maxDriftMs) * 1.5),
            signatureEncoding: opts.signatureEncoding ?? DEFAULTS.signatureEncoding,
            secretResolver: opts.secretResolver,
            signedRoutes: opts.signedRoutes ?? [],
        };
        this.compiledSigned = this.config.signedRoutes.map((p) => (0, util_js_1.compileGlob)(p.toLowerCase()));
        // ~16k nonces is plenty for typical drift window sizes; at 5s TTL and
        // ~1k rps on unsigned-after fallback, ~4096 is the high water mark.
        this.fallbackNonces = new util_js_1.LruMap(16_384);
    }
    /** Returns true iff the route's `${method} ${path}` matches a signed pattern,
     *  or if all routes are signed (empty `signedRoutes`). */
    isSignedRoute(ctx) {
        if (this.config.signedRoutes.length === 0)
            return true;
        const subject = (ctx.routeKey ?? ctx.method + ' ' + ctx.path).toLowerCase();
        return this.compiledSigned.some((m) => m(subject));
    }
    /**
     * Verifies the request integrity. Returns a `Result<HmacDecision>`.
     * The orchestrator maps non-OK cases to HTTP 401/403 with a specific
     * `rejectKind` for telemetry.
     */
    async verify(ctx) {
        if (!this.isSignedRoute(ctx)) {
            return (0, types_js_1.ok)({ valid: true, rejectKind: 'unsigned_route', keyId: null });
        }
        const h = ctx.headers;
        const keyId = headerOf(h, this.config.keyIdHeader);
        const signature = headerOf(h, this.config.signatureHeader);
        const tsStr = headerOf(h, this.config.timestampHeader);
        const nonce = headerOf(h, this.config.nonceHeader);
        if (keyId.length === 0) {
            return reject('missing_key_id', 401, 'Missing X-Key-Id');
        }
        if (signature.length === 0) {
            return reject('missing_signature', 401, 'Missing X-Signature');
        }
        if (tsStr.length === 0) {
            return reject('missing_timestamp', 401, 'Missing X-Timestamp');
        }
        if (nonce.length === 0) {
            return reject('missing_nonce', 401, 'Missing X-Nonce');
        }
        // Timestamp parse — accept seconds or ms.
        const tsNum = Number(tsStr);
        if (!Number.isFinite(tsNum) || tsNum <= 0) {
            return reject('malformed_timestamp', 401, 'X-Timestamp is not a valid epoch');
        }
        // Heuristic: if number has >= 13 digits treat as ms, else seconds.
        const tsMs = tsStr.length >= 13 ? tsNum : tsNum * 1000;
        const driftMs = Math.abs(Date.now() - tsMs);
        if (driftMs > this.config.maxDriftMs) {
            return reject('timestamp_drift', 401, `timestamp drift ${driftMs}ms exceeds ${this.config.maxDriftMs}ms`);
        }
        // Resolve secret.
        let secret;
        try {
            secret = await this.config.secretResolver(keyId);
        }
        catch {
            return reject('unknown_key', 401, `secret resolver threw for key ${keyId}`);
        }
        if (!secret || !secret.secret || secret.secret.length === 0) {
            return reject('unknown_key', 401, `no secret for key ${keyId}`);
        }
        // Nonce atomic claim via Redis Lua. Fail-soft on breaker OPEN.
        const nonceHash = (0, util_js_1.sha256Hex)(nonce);
        const nonceKey = this.redis.key('nonce:' + nonceHash);
        const claimRet = await this.redis.evalsha(lua_scripts_js_1.NONCE_CHECK_LUA, [nonceKey], [
            String(this.config.nonceTtlMs),
            '1',
        ]);
        let nonceFresh = false;
        if (claimRet.ok) {
            nonceFresh = (0, lua_scripts_js_1.decodeNonceResult)(claimRet.value);
        }
        else {
            // Fail-soft: LRU in memory.
            const now = Date.now();
            const existing = this.fallbackNonces.get(nonceHash);
            if (existing !== undefined && now - existing < this.config.nonceTtlMs) {
                nonceFresh = false; // seen -> replay
            }
            else {
                this.fallbackNonces.set(nonceHash, now);
                nonceFresh = true;
            }
        }
        if (!nonceFresh) {
            return reject('replay_detected', 403, `nonce reuse detected (key=${keyId})`);
        }
        // Reconstruct StringToSign.
        const verb = ctx.method.toUpperCase();
        const path = ctx.path;
        const tsString = tsStr; // use the raw input value (matches client's choice).
        const rawBody = ctx.rawBody;
        const stringToSign = verb + '\n' + path + '\n' + tsString + '\n' + nonce + '\n' + rawBody.toString('utf8');
        // Always compute the *raw* 32-byte digest (a Buffer). We then compare
        // the candidate (which the client encoded in 'hex' or 'base64') against
        // this canonical byte buffer. The encoding only affects how we translate
        // the candidate's string back into 32 bytes for the timing-safe compare.
        const serverDigest = (0, node_crypto_1.createHmac)('sha256', secret.secret).update(stringToSign, 'utf8').digest();
        // Constant-time compare.
        const sigEqual = compareHexB64(signature, serverDigest, this.config.signatureEncoding);
        if (!sigEqual) {
            return reject('signature_invalid', 403, 'HMAC signature does not match');
        }
        return (0, types_js_1.ok)({ valid: true, rejectKind: null, keyId });
    }
    /** Maps a non-OK reject to a SecurityError (used by the orchestrator). */
    static rejectKindToError(kind, message, ctx) {
        let statusCode = 401;
        let errorKind = 'signature_invalid';
        switch (kind) {
            case 'timestamp_drift':
                errorKind = 'timestamp_drift';
                statusCode = 401;
                break;
            case 'replay_detected':
                errorKind = 'replay_detected';
                statusCode = 403;
                break;
            case 'signature_invalid':
                errorKind = 'signature_invalid';
                statusCode = 403;
                break;
            case 'unknown_key':
                errorKind = 'signature_invalid';
                statusCode = 401;
                break;
            default:
                errorKind = 'signature_invalid';
                statusCode = 401;
        }
        return {
            kind: errorKind,
            message,
            statusCode,
            context: {
                path: ctx.path,
                method: ctx.method,
                kind,
            },
        };
    }
}
exports.HmacGuard = HmacGuard;
function reject(rejectKind, statusCode, message) {
    void rejectKind;
    void statusCode;
    return (0, types_js_1.err)({ kind: 'signature_invalid', message, statusCode, context: { rejectKind } });
}
function headerOf(h, name) {
    const k = name.toLowerCase();
    const v = h[k];
    if (v === undefined)
        return '';
    if (Array.isArray(v))
        return v.length > 0 ? String(v[0]).trim() : '';
    return String(v).trim();
}
/**
 * Compares two hex/base64-encoded HMAC signatures in constant time *at the
 * byte level*. We always decode both sides to fixed-length buffers (sha256 is
 * 32 bytes; hex is 64 chars; base64 is 44 chars with `=` padding).
 *
 * Length is leaked only at the buffer level, which is fine since legitimate
 * HMACs always have the canonical length. If candidate is malformed we still
 * hash-allocation a same-length buffer and run `timingSafeEqual` against it,
 * so the *fast path* timing does not destabilize based on length pre-checks.
 */
function compareHexB64(candidate, serverDigest, encoding) {
    if (candidate.length === 0)
        return false;
    let candBuf;
    let serverBuf;
    if (encoding === 'hex') {
        if (!/^[0-9a-fA-F]+$/.test(candidate)) {
            // malformed hex — still process to keep timing balanced; the comparison
            // will fail because the byte pattern won't equal.
            candBuf = Buffer.alloc(serverDigest.length);
            candidate.slice(0, serverDigest.length * 2).split('').forEach((c, i) => {
                if (i < candBuf.length)
                    candBuf[i] = c.charCodeAt(0) & 0xff;
            });
        }
        else {
            const wantedLen = serverDigest.length * 2;
            let norm = candidate;
            if (norm.length !== wantedLen) {
                // Pad or truncate to canonical length; we never reveal which side
                // mismatched.
                norm = (norm + '0'.repeat(wantedLen)).slice(0, wantedLen);
            }
            candBuf = Buffer.from(norm, 'hex');
        }
        serverBuf = serverDigest;
    }
    else {
        const expectedLen = Math.ceil((serverDigest.length * 4) / 3) + (((serverDigest.length * 4) % 3) > 0 ? 1 : 0);
        const paddedLen = Math.ceil(serverDigest.length / 3) * 4;
        void expectedLen;
        let norm = candidate.replace(/\s+/g, '');
        const padNeed = (4 - (norm.length % 4)) % 4;
        if (padNeed > 0)
            norm = norm + '='.repeat(padNeed);
        if (norm.length !== paddedLen) {
            // truncate/pad to canonical base64 sha256 length (44 chars).
            const canon = (norm + '='.repeat(paddedLen)).slice(0, paddedLen);
            norm = canon;
        }
        try {
            const decoded = Buffer.from(norm, 'base64');
            // Bring to canonical length with zero-fill so timing compares equal.
            if (decoded.length !== serverDigest.length) {
                candBuf = Buffer.alloc(serverDigest.length);
                decoded.copy(candBuf, 0, 0, Math.min(decoded.length, serverDigest.length));
            }
            else {
                candBuf = decoded;
            }
        }
        catch {
            candBuf = Buffer.alloc(serverDigest.length);
        }
        serverBuf = serverDigest;
    }
    // Length is *guaranteed* equal at this point — both buffers are sized to
    // the canonical sha256 byte length (32). `timingSafeEqual` throws on
    // length mismatch, but here lengths equal by construction, so the safe call
    // is unconditional.
    if (candBuf.length !== serverBuf.length) {
        // Paranoia: should not happen — but if it does, never reveal which side
        // via the throw message; produce a fixed timing comparison instead.
        const minLen = Math.min(candBuf.length, serverBuf.length);
        try {
            return (0, node_crypto_1.timingSafeEqual)(candBuf.subarray(0, minLen), serverBuf.subarray(0, minLen));
        }
        catch {
            return false;
        }
    }
    try {
        return (0, node_crypto_1.timingSafeEqual)(candBuf, serverBuf);
    }
    catch {
        return false;
    }
}
//# sourceMappingURL=hmac-guard.js.map