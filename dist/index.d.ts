/**
 * @guox / index.ts — public API surface.
 */
export { Guox } from './guox.js';
export type { NextOutcome } from './guox.js';
export { createGuox } from './factory.js';
export { buildExpressAdapter, ExpressAdapter } from './adapters/express.js';
export type { ExpressLikeRequest, ExpressLikeResponse, ExpressNext, ExpressAdapterOptions, } from './adapters/express.js';
export { buildFastifyAdapter, FastifyAdapter, } from './adapters/fastify.js';
export type { FastifyLikeRequest, FastifyLikeReply, FastifyNext, FastifyAdapterOptions, } from './adapters/fastify.js';
export { Sanitizer } from './modules/sanitizer.js';
export type { SanitizerResult } from './modules/sanitizer.js';
export { RateLimiter } from './modules/rate-limiter.js';
export type { RateLimitDecision } from './types.js';
export { IpReputation } from './modules/ip-reputation.js';
export type { IpReputationDecision } from './modules/ip-reputation.js';
export { Ja4Bridge, DEFAULT_JA4_FAMILY_MAP } from './modules/ja4-bridge.js';
export type { Ja4Decision } from './modules/ja4-bridge.js';
export { HmacGuard } from './modules/hmac-guard.js';
export type { HmacDecision, HmacRejectKind } from './modules/hmac-guard.js';
export { SessionShield } from './modules/session-shield.js';
export type { SessionShieldDecision } from './modules/session-shield.js';
export { SchemaDrift } from './modules/schema-drift.js';
export type { SchemaDriftResult } from './modules/schema-drift.js';
export { RedisClient } from './redis-client.js';
export { RATE_LIMIT_LUA, NONCE_CHECK_LUA, IP_REPUTATION_LUA, JWT_BLACKLIST_LUA, decodeRateLimitResult, decodeNonceResult, decodeIpReputationResult, } from './lua-scripts.js';
export { CpuLoadSampler, LruMap, MemoryTokenBucket } from './util.js';
export type * from './types.js';
export { Identity, NonceHash, Ja4Fingerprint, FingerprintHash, ok, err } from './types.js';
export { SecurityEventBus, defaultJsonConsoleSink } from './events.js';
//# sourceMappingURL=index.d.ts.map