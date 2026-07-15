"use strict";
/**
 * @guox / modules / ip-reputation.ts — Premium Feature
 *
 * IP Reputation IP-set caching. Tracks consecutive security violations per IP
 * and temporarily blocks IPs that exceed the threshold (default: 3 within 5
 * minutes triggers a 10-minute block). The hot path on each request is a
 * *synchronous* in-memory LRU lookup that doubles as a write-through mirror
 * of the durable Redis block set.
 *
 * Why bother (given rate limiter already throttles)?
 *   - rate limiter is *per identity*, not per IP. Attackers churning thousands
 *     of throwaway API keys would each get a fresh credit pool. IP reputation
 *     closes that gap by collapsing traffic from one source on reputation
 *     signals rather than identity.
 *   - the cost of doing this *after* Redis is down (breaker OPEN) is a single
 *     `Map.has` lookup — O(1) and never blocks the event loop.
 *
 * Mirror strategy:
 *   - Read fast-path: pure in-memory `Map<ip, BlockEntry>`.
 *   - On block, write-through to Redis (eventually consistent; if Redis is
 *     OPEN, the in-memory block still stands for the duration the server is up).
 *   - On startup, mirrors can be marked "stale" so the orchestrator can
 *     repopulate them from Redis via a one-time `snapshot()`. The default
 *     is to learn blocks lazily from peers through `isBlocked()` hits — this
 *     is acceptable since stale in-memory blocks decay naturally.
 *
 * Adapts to most workloads out-of-the-box without tuning.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.IpReputation = void 0;
const types_js_1 = require("../types.js");
const lua_scripts_js_1 = require("../lua-scripts.js");
const util_js_1 = require("../util.js");
const DEFAULTS = {
    violationThreshold: 3,
    violationWindowSeconds: 300,
    blockTtlSeconds: 600,
    memoryCacheSize: 8192,
    violationEvents: [
        'rate_limited',
        'replay_detected',
        'signature_invalid',
        'session_hijack',
        'fingerprint_mismatch',
        'prototype_pollution',
        'payload_too_deep',
        'tls_spoofing',
        'schema_drift',
    ],
};
class IpReputation {
    config;
    blockMap;
    /** Per-IP *consecutive* violation counter (in-memory first, mirrored to
     *  Redis asynchronously). */
    violationTimestamps = new util_js_1.LruMap(4096);
    redis;
    /** When dirty=true, the orchestrator emits a write-through to the mirror. */
    dirty = false;
    constructor(redis, opts) {
        this.redis = redis;
        const memCap = opts?.memoryCacheSize ?? DEFAULTS.memoryCacheSize;
        this.config = {
            violationThreshold: opts?.violationThreshold ?? DEFAULTS.violationThreshold,
            violationWindowSeconds: opts?.violationWindowSeconds ?? DEFAULTS.violationWindowSeconds,
            blockTtlSeconds: opts?.blockTtlSeconds ?? DEFAULTS.blockTtlSeconds,
            memoryCacheSize: memCap,
            violationEvents: opts?.violationEvents ?? DEFAULTS.violationEvents,
        };
        this.blockMap = new util_js_1.LruMap(memCap);
    }
    _blockMapSizeForCompat = () => this.blockMap.size;
    /** Fast path: O(1) synchronous check. Never throws. */
    isBlocked(ctx) {
        const ip = (0, util_js_1.canonicalizeIp)(ctx.clientIp);
        const entry = this.blockMap.get(ip);
        const now = (0, util_js_1.nowSec)();
        if (entry && entry.unblockAt > now) {
            return (0, types_js_1.ok)({
                blocked: true,
                blockExpiresIn: entry.unblockAt - now,
                freshBlock: false,
            });
        }
        if (entry && entry.unblockAt <= now) {
            // Stale entry — opportunistically evict.
            this.blockMap.delete(ip);
        }
        return (0, types_js_1.ok)({
            blocked: false,
            blockExpiresIn: 0,
            freshBlock: false,
        });
    }
    /** Records a security violation associated with the request's IP. Triggers a
     *  block when `violationThreshold` is hit. Returns the resulting decision
     *  (which may be `blocked: true` if this call escalated). */
    async recordViolation(ctx, eventKind) {
        if (!this.config.violationEvents.includes(eventKind)) {
            return { blocked: false, blockExpiresIn: 0, freshBlock: false };
        }
        const ip = (0, util_js_1.canonicalizeIp)(ctx.clientIp);
        const now = (0, util_js_1.nowSec)();
        const window = this.config.violationWindowSeconds;
        const threshold = this.config.violationThreshold;
        const blockTtl = this.config.blockTtlSeconds;
        // Pre-flight the in-memory block map.
        const existing = this.blockMap.get(ip);
        if (existing && existing.unblockAt > now) {
            return {
                blocked: true,
                blockExpiresIn: existing.unblockAt - now,
                freshBlock: false,
            };
        }
        // Try durable Redis-side atomic increment+block.
        const luaRet = await this.redis.evalsha(lua_scripts_js_1.IP_REPUTATION_LUA, [
            this.redis.key('iprep:viol:' + ip),
            this.redis.key('iprep:block:' + ip),
        ], [String(threshold), String(window), String(blockTtl), String(now)]);
        if (luaRet.ok) {
            const r = (0, lua_scripts_js_1.decodeIpReputationResult)(luaRet.value);
            if (r.blockedNow) {
                this.blockMap.set(ip, {
                    unblockAt: now + blockTtl,
                    source: 'redis',
                });
                this.dirty = true;
                return { blocked: true, blockExpiresIn: blockTtl, freshBlock: true };
            }
            return { blocked: false, blockExpiresIn: 0, freshBlock: false };
        }
        // Fail-soft path: in-memory violation bucket. Generates local blocks.
        let bucket = this.violationTimestamps.get(ip);
        if (!bucket) {
            bucket = [];
            this.violationTimestamps.set(ip, bucket);
        }
        // Drop expired timestamps.
        const cutoff = now - window;
        const kept = bucket.filter((t) => t > cutoff);
        kept.push(now);
        this.violationTimestamps.set(ip, kept);
        if (kept.length >= threshold) {
            // Escalate to memory block.
            const unblockAt = now + blockTtl;
            this.blockMap.set(ip, { unblockAt, source: 'memory' });
            this.violationTimestamps.delete(ip);
            return { blocked: true, blockExpiresIn: blockTtl, freshBlock: true };
        }
        return { blocked: false, blockExpiresIn: 0, freshBlock: false };
    }
    /** Allows the orchestrator (or admin route) to manually unblock an IP. */
    unblock(ipRaw) {
        const ip = (0, util_js_1.canonicalizeIp)(ipRaw);
        this.blockMap.delete(ip);
        this.violationTimestamps.delete(ip);
        // Best-effort: clear the Redis side as well.
        void this.redis.evalsha(`redis.call('DEL', KEYS[1], KEYS[2]); return 1`, [
            this.redis.key('iprep:block:' + ip),
            this.redis.key('iprep:viol:' + ip),
        ], []);
    }
    /** Compact snapshot for diagnostics / metrics. */
    snapshot() {
        return { blocked: this.blockMap.size, violations: this.violationTimestamps.size };
    }
    /** True when the in-memory mirror should be re-pushed to Redis. */
    isDirty() {
        return this.dirty;
    }
    clearDirty() {
        this.dirty = false;
    }
}
exports.IpReputation = IpReputation;
//# sourceMappingURL=ip-reputation.js.map