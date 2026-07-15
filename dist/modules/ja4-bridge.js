"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.Ja4Bridge = exports.DEFAULT_JA4_FAMILY_MAP = void 0;
const types_js_1 = require("../types.js");
const util_js_1 = require("../util.js");
/* ------------------------------------------------------------------ *
 * Default family map — minimal but pragmatic set covering the major
 * desktop + mobile browser families with their canonical JA4 prefixes.
 *
 * These are *prefixes* only — the rest of the JA4 string varies per version.
 * Consult FoxIO/JP's JA4 spec for the canonical prefixes.
 * ------------------------------------------------------------------ */
exports.DEFAULT_JA4_FAMILY_MAP = {
    // Chrome on macOS / Linux — uses GREASE so the leading "t13" is fixed;
    // ciphers `d1516h2` is the Chrome stable since ~M109.
    t13d1516h2: ['chrome', 'edge'],
    t13d1614h2: ['chrome', 'edge'],
    // Chrome on Windows.
    t13d1516h2_b0da82dd2788: ['chrome'],
    // Firefox stable — extension set differs from Chrome.
    t13d1715h2: ['firefox'],
    t13d1716h2: ['firefox'],
    // Safari — uses ALPN h2 only on recent macOS; cipher set is older-style.
    t13d1416h2: ['safari'],
    t13d1316h2: ['safari'],
    t12d1416h2: ['safari'],
    // Mobile Safari (iOS).
    t13d1515h2: ['safari'],
    // Mobile Chrome (Android).
    t13d3016h2: ['chrome'],
    // Curl / node-fetch / python-requests / Go-http-client:listed here so we
    // can flag a desktop-Chrome UA paired with a tooling JA4 prefix.
    t13i1715h2: ['other'], // python-requests HTTP/1.1
    t13i0809h2: ['other'], // Go http-client stdlib
    t13i0e0ah2: ['other'], // node-fetch / node-tls default
    // Headless Chrome / Puppeteer *sometimes* advertises desktop UA but does
    // not authorize h2 negotiation the same way; in practice we see UA
    // mismatch flag catches Puppeteer via Sec-CH-UA-Mobile.
};
const DEFAULTS = {
    jaHeader: 'x-ja4-fingerprint',
    alternateJaHeaders: ['cf-ja4-fingerprint', 'x-ja3-fingerprint'],
    familyMap: exports.DEFAULT_JA4_FAMILY_MAP,
    onMismatch: 'block',
    excludeRoutes: ['/health', '/healthz', '/readyz', '/livez'],
};
class Ja4Bridge {
    config;
    excludes;
    constructor(opts) {
        this.config = {
            jaHeader: opts?.jaHeader ?? DEFAULTS.jaHeader,
            alternateJaHeaders: opts?.alternateJaHeaders ?? DEFAULTS.alternateJaHeaders,
            familyMap: opts?.familyMap ?? DEFAULTS.familyMap,
            onMismatch: opts?.onMismatch ?? DEFAULTS.onMismatch,
        };
        const excludePatterns = (opts?.excludeRoutes ?? DEFAULTS.excludeRoutes).map((p) => (p.includes('*') || p.includes('?') ? p : p + '*'));
        this.excludes = excludePatterns.map((p) => (0, util_js_1.compileGlob)(p.toLowerCase()));
    }
    /** Resolves the JA4/JA3 fingerprint from the request headers; falls back to
     *  the canonical `jaFingerprint` slot the context-bootstrap module pre-computed. */
    extractFingerprint(ctx) {
        if (ctx.jaFingerprint.length > 0)
            return ctx.jaFingerprint;
        const candidates = [this.config.jaHeader, ...this.config.alternateJaHeaders];
        for (let i = 0; i < candidates.length; i++) {
            const v = (0, util_js_1.header)(ctx.headers, candidates[i]);
            if (v.length > 0)
                return v;
        }
        return '';
    }
    /** Static UA -> BrowserFamily detection (no Redis, no async). */
    classifyUserAgent(ua) {
        if (ua.length === 0)
            return 'other';
        // Order matters: Edge must be detected before Chrome (UA contains
        // both "Edg" and "Chrome"), and Chrome before Safari.
        if (/\bedg\/|edge?\/|microsoft\s+edge/i.test(ua))
            return 'edge';
        // Chrome: typed in as chrome/<ver>
        if (/chrome\/[0-9]/i.test(ua))
            return 'chrome';
        if (/firefox\/[0-9]/i.test(ua))
            return 'firefox';
        if (/\s(version\/[0-9].*safari|safari\/[0-9])/i.test(ua) || /^mozilla\/[0-9].*safari/i.test(ua)) {
            return 'safari';
        }
        return 'other';
    }
    /**
     * Looks up a JA4 prefix (up to wherever the chars are stable across the
     * browser's minor release) in the family map. We try progressively longer
     * prefix matches because the full JA4 string's middle hash often varies
     * across minor browser versions.
     */
    lookupFamilies(ja4) {
        if (ja4.length === 0)
            return null;
        const keys = Object.keys(this.config.familyMap);
        // Sort keys by descending length to match the most specific first.
        keys.sort((a, b) => b.length - a.length);
        for (let i = 0; i < keys.length; i++) {
            const k = keys[i];
            if (ja4.startsWith(k)) {
                return [...this.config.familyMap[k]];
            }
        }
        return null;
    }
    verify(ctx) {
        // Exempt routes: don't enforce JA4 on health-check endpoints — those are
        // routinely called by k8s/docker probes without proper TLS hints.
        const subject = ctx.path.toLowerCase();
        const exempt = this.excludes.some((m) => m(subject));
        if (exempt) {
            return (0, types_js_1.ok)({
                ok: true,
                family: 'other',
                ja4: '',
                mismatch: false,
                exempt: true,
            });
        }
        const ja4 = this.extractFingerprint(ctx);
        const family = this.classifyUserAgent(ctx.userAgent);
        if (ja4.length === 0) {
            // No fingerprint supplied. We *do not* exit OK silently for non-other
            // families — production hardening expects the proxy to inject JA4; its
            // absence on a desktop-Chrome UA is a strong signal of a misconfigured
            // or spoofing client. But we don't strictly fail: we hand off to
            // onMismatch as flag.
            if (family === 'other') {
                return (0, types_js_1.ok)({
                    ok: true,
                    family,
                    ja4,
                    mismatch: false,
                    exempt: false,
                });
            }
            if (this.config.onMismatch === 'block') {
                return (0, types_js_1.err)({
                    kind: 'tls_spoofing',
                    message: 'JA4 fingerprint missing for desktop-UA client',
                    statusCode: 403,
                    context: { ua: ctx.userAgent.slice(0, 64), family },
                });
            }
            return (0, types_js_1.ok)({
                ok: true,
                family,
                ja4,
                mismatch: true,
                exempt: false,
            });
        }
        const allowedFamilies = this.lookupFamilies(ja4);
        if (allowedFamilies === null) {
            // Unknown JA4 — can be a new browser or a non-browser tool (curl, etc).
            // Only flag when there's a real UA-family claim worth cross-checking.
            if (family !== 'other' && this.config.onMismatch === 'block') {
                return (0, types_js_1.err)({
                    kind: 'tls_spoofing',
                    message: 'JA4 fingerprint unknown while UA claims a recognized desktop browser',
                    statusCode: 403,
                    context: { ua: ctx.userAgent.slice(0, 64), family, ja4 },
                });
            }
            return (0, types_js_1.ok)({ ok: true, family, ja4, mismatch: family !== 'other', exempt: false });
        }
        const mismatch = !allowedFamilies.includes(family);
        if (mismatch && this.config.onMismatch === 'block') {
            return (0, types_js_1.err)({
                kind: 'tls_spoofing',
                message: `JA4 family set ${JSON.stringify(allowedFamilies)} does not include UA-derived family "${family}"`,
                statusCode: 403,
                context: { ua: ctx.userAgent.slice(0, 64), family, ja4: ja4.slice(0, 64) },
            });
        }
        return (0, types_js_1.ok)({ ok: true, family, ja4, mismatch, exempt: false });
    }
}
exports.Ja4Bridge = Ja4Bridge;
//# sourceMappingURL=ja4-bridge.js.map