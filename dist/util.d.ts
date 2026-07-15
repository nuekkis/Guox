/**
 * @guox / util.ts
 *
 * Stateless helpers shared across modules. Kept dependency-free and synchronous
 * where possible to keep the hot path off the event loop. Every function here
 * is type-safe in strict mode and tolerates malformed inputs (returning
 * deterministic fallbacks rather than throwing).
 */
/**
 * Minimal but correct glob matcher. Supports `*` (any chars except `/`) and
 * `?` (single char) and `**` (any chars incl `/`). Returns a boolean match
 * function precompiled for performance; meant for:
 *  - route patterns (`POST /users/*`).
 *  - signed-route globs.
 *
 * Pattern examples:
 *   "POST /users/*"           -> matches "POST /users/42" but not "POST /users/42/x"
 *   "POST /users/**"          -> matches "POST /users/42/x"
 *   "GET /health"             -> exact
 *
 * Note: a pattern without a method prefix matches any method.
 */
export declare function compileGlob(pattern: string): (subject: string) => boolean;
/** Case-insensitive header read with a single pre-lowercased lookup map. */
export declare function header(headers: Readonly<Record<string, string | string[] | undefined>>, name: string): string;
/** Returns the sha256 hex of any string. */
export declare function sha256Hex(input: string): string;
/** Returns the sha256 hex of any Buffer. */
export declare function sha256Buf(input: Buffer): string;
/** Generates a fresh url-safe request id. */
export declare function freshRequestId(): string;
export declare function timingSafeStringEq(a: string, b: string): boolean;
export declare function timingSafeBufEq(a: Buffer, b: Buffer): boolean;
export declare function canonicalizeIp(raw: string): string;
/**
 * Returns the subnet mask used for fingerprinting:
 *   - IPv4: first three octets (i.e. /24).
 *   - IPv6: first three hextets (i.e. /48).
 *   - Unknown -> best effort: full string.
 */
export declare function ipToSubnet(ipRaw: string): string;
/**
 * Resolves the canonical client IP honoring `X-Forwarded-For` up to N hops.
 * Rightmost trusted hop is removed first; the leftmost non-empty address of
 * the remaining prefix is the canonical client IP.
 */
export declare function resolveClientIp(headers: Readonly<Record<string, string | string[] | undefined>>, rawIp: string | undefined, trustProxyHops: number): string;
export declare class LruMap<K, V> {
    private readonly store;
    private readonly max;
    constructor(max: number);
    get size(): number;
    get(key: K): V | undefined;
    set(key: K, value: V): void;
    has(key: K): boolean;
    delete(key: K): boolean;
    clear(): void;
    entries(): IterableIterator<[K, V]>;
}
export interface MemoryBucketSnapshot {
    tokens: number;
    lastRefill: number;
}
export declare class MemoryTokenBucket {
    capacity: number;
    refillTokensPerSec: number;
    tokens: number;
    lastRefill: number;
    constructor(capacity: number, refillPerWindow: number, windowSec: number);
    /** Tries to charge `cost` tokens. Returns the post-charge remaining tokens
     * (or -1 if rejected). Synchronized by the Node event loop's single thread. */
    charge(cost: number): number;
    snapshot(): MemoryBucketSnapshot;
}
export declare class CpuLoadSampler {
    private lastUser;
    private lastSystem;
    private lastAt;
    private cores;
    private smoothed;
    constructor(cores?: number);
    /** Returns the exponentially-smoothed normalized load in [0,1]. */
    sample(): number;
}
export declare function nowSec(): number;
export declare function nowMs(): number;
export declare function ceilToAtLeast1(n: number): number;
//# sourceMappingURL=util.d.ts.map