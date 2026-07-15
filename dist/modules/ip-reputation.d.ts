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
import type { IpReputationOptions, RequestContext, Result, SecurityError, SecurityEvent } from '../types.js';
import type { RedisClient } from '../redis-client.js';
export interface IpReputationDecision {
    readonly blocked: boolean;
    /** Seconds until the current block expires (0 if not blocked). */
    readonly blockExpiresIn: number;
    /** True if this is a write-through decision (e.g. a brand-new block). */
    readonly freshBlock: boolean;
}
export declare class IpReputation {
    private readonly config;
    private readonly blockMap;
    /** Per-IP *consecutive* violation counter (in-memory first, mirrored to
     *  Redis asynchronously). */
    private readonly violationTimestamps;
    private readonly redis;
    /** When dirty=true, the orchestrator emits a write-through to the mirror. */
    private dirty;
    constructor(redis: RedisClient, opts?: IpReputationOptions);
    readonly _blockMapSizeForCompat: () => number;
    /** Fast path: O(1) synchronous check. Never throws. */
    isBlocked(ctx: RequestContext): Result<IpReputationDecision, SecurityError>;
    /** Records a security violation associated with the request's IP. Triggers a
     *  block when `violationThreshold` is hit. Returns the resulting decision
     *  (which may be `blocked: true` if this call escalated). */
    recordViolation(ctx: RequestContext, eventKind: SecurityEvent['kind']): Promise<IpReputationDecision>;
    /** Allows the orchestrator (or admin route) to manually unblock an IP. */
    unblock(ipRaw: string): void;
    /** Compact snapshot for diagnostics / metrics. */
    snapshot(): {
        blocked: number;
        violations: number;
    };
    /** True when the in-memory mirror should be re-pushed to Redis. */
    isDirty(): boolean;
    clearDirty(): void;
}
//# sourceMappingURL=ip-reputation.d.ts.map