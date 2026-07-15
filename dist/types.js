"use strict";
/**
 * @guox / types.ts
 *
 * Core type surface for the Guox security layer. Every public symbol the
 * integrator touches originates here. Strict-mode TypeScript throughout.
 *
 * Design principles:
 *  - `unknown` over `any` everywhere possible.
 *  - Branded nominal types for security-sensitive scalars (Identity, Nonce).
 *  - Tagged unions for results so middleware branching is exhaustive-checked.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.FingerprintHash = exports.Ja4Fingerprint = exports.NonceHash = exports.Identity = exports.err = exports.ok = void 0;
const ok = (value) => ({ ok: true, value });
exports.ok = ok;
const err = (error) => ({
    ok: false,
    error,
});
exports.err = err;
/* ------------------------------------------------------------------ *
 * Misc helpers — brand constructors exported for internal reuse
 * ------------------------------------------------------------------ */
const Identity = (s) => s;
exports.Identity = Identity;
const NonceHash = (s) => s;
exports.NonceHash = NonceHash;
const Ja4Fingerprint = (s) => s;
exports.Ja4Fingerprint = Ja4Fingerprint;
const FingerprintHash = (s) => s;
exports.FingerprintHash = FingerprintHash;
//# sourceMappingURL=types.js.map