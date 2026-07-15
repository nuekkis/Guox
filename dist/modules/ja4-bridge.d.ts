/**
 * @guox / modules / ja4-bridge.ts — Module 5
 *
 * Reverse-proxy trust & JA4/TLS fingerprinting bridge.
 *
 * Reverse proxies (Cloudflare, Nginx with ja4 plugin, AWS CloudFront) terminate
 * TLS, so the application never sees the raw ClientHello. Instead, they inject
 * the computed JA3/JA4 digest as a request header. This module:
 *   - extracts that fingerprint from a configurable header chain,
 *   - normalizes the request's User-Agent to a stable *browser family*
 *     (chrome/firefox/safari/edge/other),
 *   - consults an in-process `Ja4FamilyMap` (a small, fast-lookup map keyed by
 *     the *prefix* of the JA4 string — JA4 prefixes encode the hash of
 *     specific extensions that are stable across versions of the same
 *     browser family),
 *   - flags any inconsistency as a `tls_spoofing` security event, returns
 *     403 (block) or simply logs (flag).
 *
 * Why prefix lookup rather than full JA4?
 *   - JA4 has the form `<tls-ver>_<ciphers-hex>_<ext-hex>_<alpn-hex>`. The
 *     middle two fields (ciphers/extensions) shift slightly between browser
 *     minor releases, but the *prefix* (e.g. `t13d1516h2`) is stable. Doing
 *     prefix matches tolerates rolling upgrades of a browser's TLS stack,
 *     which would otherwise generate false positives that exasperate legitimate
 *     users.
 *
 * The default map is conservative: only well-known desktop patterns are
 * registered. Anything not in the map is *not* flagged — only a UA mismatch
 * between a known pattern families is flagged.
 */
import type { BrowserFamily, Ja4FamilyMap, Ja4Options, RequestContext, Result, SecurityError } from '../types.js';
export declare const DEFAULT_JA4_FAMILY_MAP: Ja4FamilyMap;
export interface Ja4Decision {
    /** True if the request should proceed. */
    readonly ok: boolean;
    readonly family: BrowserFamily;
    readonly ja4: string;
    readonly mismatch: boolean;
    /** True if exempt by route. */
    readonly exempt: boolean;
}
export declare class Ja4Bridge {
    private readonly config;
    private readonly excludes;
    constructor(opts?: Ja4Options);
    /** Resolves the JA4/JA3 fingerprint from the request headers; falls back to
     *  the canonical `jaFingerprint` slot the context-bootstrap module pre-computed. */
    private extractFingerprint;
    /** Static UA -> BrowserFamily detection (no Redis, no async). */
    classifyUserAgent(ua: string): BrowserFamily;
    /**
     * Looks up a JA4 prefix (up to wherever the chars are stable across the
     * browser's minor release) in the family map. We try progressively longer
     * prefix matches because the full JA4 string's middle hash often varies
     * across minor browser versions.
     */
    private lookupFamilies;
    verify(ctx: RequestContext): Result<Ja4Decision, SecurityError>;
}
//# sourceMappingURL=ja4-bridge.d.ts.map