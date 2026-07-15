"use strict";
/**
 * @guox / index.ts — public API surface.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.defaultJsonConsoleSink = exports.SecurityEventBus = exports.err = exports.ok = exports.FingerprintHash = exports.Ja4Fingerprint = exports.NonceHash = exports.Identity = exports.MemoryTokenBucket = exports.LruMap = exports.CpuLoadSampler = exports.decodeIpReputationResult = exports.decodeNonceResult = exports.decodeRateLimitResult = exports.JWT_BLACKLIST_LUA = exports.IP_REPUTATION_LUA = exports.NONCE_CHECK_LUA = exports.RATE_LIMIT_LUA = exports.RedisClient = exports.SchemaDrift = exports.SessionShield = exports.HmacGuard = exports.DEFAULT_JA4_FAMILY_MAP = exports.Ja4Bridge = exports.IpReputation = exports.RateLimiter = exports.Sanitizer = exports.FastifyAdapter = exports.buildFastifyAdapter = exports.ExpressAdapter = exports.buildExpressAdapter = exports.createGuox = exports.Guox = void 0;
var guox_js_1 = require("./guox.js");
Object.defineProperty(exports, "Guox", { enumerable: true, get: function () { return guox_js_1.Guox; } });
var factory_js_1 = require("./factory.js");
Object.defineProperty(exports, "createGuox", { enumerable: true, get: function () { return factory_js_1.createGuox; } });
// Adapted helpers for Express / Fastify integrators.
var express_js_1 = require("./adapters/express.js");
Object.defineProperty(exports, "buildExpressAdapter", { enumerable: true, get: function () { return express_js_1.buildExpressAdapter; } });
Object.defineProperty(exports, "ExpressAdapter", { enumerable: true, get: function () { return express_js_1.ExpressAdapter; } });
var fastify_js_1 = require("./adapters/fastify.js");
Object.defineProperty(exports, "buildFastifyAdapter", { enumerable: true, get: function () { return fastify_js_1.buildFastifyAdapter; } });
Object.defineProperty(exports, "FastifyAdapter", { enumerable: true, get: function () { return fastify_js_1.FastifyAdapter; } });
// Module-level public surface for advanced users (e.g. unit testing).
var sanitizer_js_1 = require("./modules/sanitizer.js");
Object.defineProperty(exports, "Sanitizer", { enumerable: true, get: function () { return sanitizer_js_1.Sanitizer; } });
var rate_limiter_js_1 = require("./modules/rate-limiter.js");
Object.defineProperty(exports, "RateLimiter", { enumerable: true, get: function () { return rate_limiter_js_1.RateLimiter; } });
var ip_reputation_js_1 = require("./modules/ip-reputation.js");
Object.defineProperty(exports, "IpReputation", { enumerable: true, get: function () { return ip_reputation_js_1.IpReputation; } });
var ja4_bridge_js_1 = require("./modules/ja4-bridge.js");
Object.defineProperty(exports, "Ja4Bridge", { enumerable: true, get: function () { return ja4_bridge_js_1.Ja4Bridge; } });
Object.defineProperty(exports, "DEFAULT_JA4_FAMILY_MAP", { enumerable: true, get: function () { return ja4_bridge_js_1.DEFAULT_JA4_FAMILY_MAP; } });
var hmac_guard_js_1 = require("./modules/hmac-guard.js");
Object.defineProperty(exports, "HmacGuard", { enumerable: true, get: function () { return hmac_guard_js_1.HmacGuard; } });
var session_shield_js_1 = require("./modules/session-shield.js");
Object.defineProperty(exports, "SessionShield", { enumerable: true, get: function () { return session_shield_js_1.SessionShield; } });
var schema_drift_js_1 = require("./modules/schema-drift.js");
Object.defineProperty(exports, "SchemaDrift", { enumerable: true, get: function () { return schema_drift_js_1.SchemaDrift; } });
// Redis / Lua plumbing (for ops scripts, integration tests, monitoring).
var redis_client_js_1 = require("./redis-client.js");
Object.defineProperty(exports, "RedisClient", { enumerable: true, get: function () { return redis_client_js_1.RedisClient; } });
var lua_scripts_js_1 = require("./lua-scripts.js");
Object.defineProperty(exports, "RATE_LIMIT_LUA", { enumerable: true, get: function () { return lua_scripts_js_1.RATE_LIMIT_LUA; } });
Object.defineProperty(exports, "NONCE_CHECK_LUA", { enumerable: true, get: function () { return lua_scripts_js_1.NONCE_CHECK_LUA; } });
Object.defineProperty(exports, "IP_REPUTATION_LUA", { enumerable: true, get: function () { return lua_scripts_js_1.IP_REPUTATION_LUA; } });
Object.defineProperty(exports, "JWT_BLACKLIST_LUA", { enumerable: true, get: function () { return lua_scripts_js_1.JWT_BLACKLIST_LUA; } });
Object.defineProperty(exports, "decodeRateLimitResult", { enumerable: true, get: function () { return lua_scripts_js_1.decodeRateLimitResult; } });
Object.defineProperty(exports, "decodeNonceResult", { enumerable: true, get: function () { return lua_scripts_js_1.decodeNonceResult; } });
Object.defineProperty(exports, "decodeIpReputationResult", { enumerable: true, get: function () { return lua_scripts_js_1.decodeIpReputationResult; } });
// CPU sampler for the adaptive rate limiter (exposed for advanced ops).
var util_js_1 = require("./util.js");
Object.defineProperty(exports, "CpuLoadSampler", { enumerable: true, get: function () { return util_js_1.CpuLoadSampler; } });
Object.defineProperty(exports, "LruMap", { enumerable: true, get: function () { return util_js_1.LruMap; } });
Object.defineProperty(exports, "MemoryTokenBucket", { enumerable: true, get: function () { return util_js_1.MemoryTokenBucket; } });
var types_js_1 = require("./types.js");
Object.defineProperty(exports, "Identity", { enumerable: true, get: function () { return types_js_1.Identity; } });
Object.defineProperty(exports, "NonceHash", { enumerable: true, get: function () { return types_js_1.NonceHash; } });
Object.defineProperty(exports, "Ja4Fingerprint", { enumerable: true, get: function () { return types_js_1.Ja4Fingerprint; } });
Object.defineProperty(exports, "FingerprintHash", { enumerable: true, get: function () { return types_js_1.FingerprintHash; } });
Object.defineProperty(exports, "ok", { enumerable: true, get: function () { return types_js_1.ok; } });
Object.defineProperty(exports, "err", { enumerable: true, get: function () { return types_js_1.err; } });
// SecurityEvent bus for users that want to ship their own sink.
var events_js_1 = require("./events.js");
Object.defineProperty(exports, "SecurityEventBus", { enumerable: true, get: function () { return events_js_1.SecurityEventBus; } });
Object.defineProperty(exports, "defaultJsonConsoleSink", { enumerable: true, get: function () { return events_js_1.defaultJsonConsoleSink; } });
//# sourceMappingURL=index.js.map