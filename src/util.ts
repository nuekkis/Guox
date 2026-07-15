/**
 * @guox / util.ts
 *
 * Stateless helpers shared across modules. Kept dependency-free and synchronous
 * where possible to keep the hot path off the event loop. Every function here
 * is type-safe in strict mode and tolerates malformed inputs (returning
 * deterministic fallbacks rather than throwing).
 */

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

/* ------------------------------------------------------------------ *
 * Glob match (tiny, allocation-free)
 * ------------------------------------------------------------------ */

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
export function compileGlob(pattern: string): (subject: string) => boolean {
  if (pattern.length === 0) return () => false;
  const re = globToRegExp(pattern);
  return (subject: string) => re.test(subject);
}

function globToRegExp(pattern: string): RegExp {
  // Escape regex specials first EXCEPT our glob metachars `*` and `?`.
  let out = '^';
  let i = 0;
  // Default `.` matches any single char except `\n`; we want literal dots in
  // paths, so escape them.
  for (; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === '*') {
      if (pattern[i + 1] === '*') {
        out += '[\\s\\S]*';
        i++; // consume **
      } else {
        out += '[^/]*';
      }
    } else if (c === '?') {
      out += '[^/]';
    } else if (c !== undefined && /[.+^${}()|[\]\\]/.test(c)) {
      out += '\\' + (c as string);
    } else {
      out += c;
    }
  }
  out += '$';
  // Anchored, case-sensitive (paths are case-sensitive).
  return new RegExp(out, '');
}

/* ------------------------------------------------------------------ *
 * Header & IP helpers
 * ------------------------------------------------------------------ */

/** Case-insensitive header read with a single pre-lowercased lookup map. */
export function header(
  headers: Readonly<Record<string, string | string[] | undefined>>,
  name: string,
): string {
  const lower = name.toLowerCase();
  const raw = headers[lower];
  if (raw === undefined) return '';
  if (Array.isArray(raw)) return raw.join(',').trim();
  return String(raw).trim();
}

/** Returns the sha256 hex of any string. */
export function sha256Hex(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

/** Returns the sha256 hex of any Buffer. */
export function sha256Buf(input: Buffer): string {
  return createHash('sha256').update(input).digest('hex');
}

/** Generates a fresh url-safe request id. */
export function freshRequestId(): string {
  return randomBytes(16).toString('base64url');
}

/* ------------------------------------------------------------------ *
 * Timing-safe string equality (constant-time on length-equal inputs)
 *
 * `crypto.timingSafeEqual` throws on length mismatch, leaking length. For
 * HMAC verification we MUST compare hashes of identical length; but to keep
 * callers ergonomic we mirror the string length first (cheap, non-secret) and
 * short-circuit with `false` on mismatch — without revealing *which side*
 * differs.
 * ------------------------------------------------------------------ */
export function timingSafeStringEq(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  const ba = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  return timingSafeEqual(ba, bb);
}

export function timingSafeBufEq(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

/* ------------------------------------------------------------------ *
 * Canonical IP canonicalization
 *
 *  - Strips IPv6 zone ids.
 *  - Normalizes private-loopback:
 *      ::1  -> "127.0.0.1"  (the v4-mapped form)
 *  - Canonicalizes a /24 (IPv4) or /48 (IPv6) subnet *prefix* (NOT the full
 *    host) so a flapping mobile client doesn't fall out of fingerprint.
 *    The full host is still recoverable from x-forwarded-for for audit; the
 *    fingerprint subsystem only needs the subnet-stable portion.
 * ------------------------------------------------------------------ */
export function canonicalizeIp(raw: string): string {
  if (raw.length === 0) return '0.0.0.0';
  let ip = raw.trim();

  // Strip IPv6 zone id "%eth0".
  const pct = ip.indexOf('%');
  if (pct !== -1) ip = ip.slice(0, pct);

  // Strip surrounding brackets.
  if (ip.startsWith('[') && ip.endsWith(']')) {
    ip = ip.slice(1, -1);
  }

  // Strip v6 v4-mapped `::ffff:1.2.3.4` to `1.2.3.4` for fingerprint stability
  // — most Node stacks report 4-mapped addresses as-is.
  const mapped = /^::ffff:([0-9.]+)$/i.exec(ip);
  if (mapped && mapped[1]) ip = mapped[1];

  // Normalize localhost.
  if (ip === '::1' || ip === '0:0:0:0:0:0:0:1') ip = '127.0.0.1';

  return ip;
}

/**
 * Returns the subnet mask used for fingerprinting:
 *   - IPv4: first three octets (i.e. /24).
 *   - IPv6: first three hextets (i.e. /48).
 *   - Unknown -> best effort: full string.
 */
export function ipToSubnet(ipRaw: string): string {
  const ip = canonicalizeIp(ipRaw);
  if (ip.includes(':')) {
    // IPv6
    const parts = ip.split(':');
    return parts.slice(0, 3).join(':').toLowerCase();
  }
  if (ip.includes('.')) {
    // IPv4
    const parts = ip.split('.');
    return parts.slice(0, 3).join('.');
  }
  return ip;
}

/**
 * Resolves the canonical client IP honoring `X-Forwarded-For` up to N hops.
 * Rightmost trusted hop is removed first; the leftmost non-empty address of
 * the remaining prefix is the canonical client IP.
 */
export function resolveClientIp(
  headers: Readonly<Record<string, string | string[] | undefined>>,
  rawIp: string | undefined,
  trustProxyHops: number,
): string {
  if (trustProxyHops <= 0) {
    return canonicalizeIp(rawIp ?? '0.0.0.0');
  }
  const xff = header(headers, 'x-forwarded-for');
  if (xff.length === 0) {
    return canonicalizeIp(rawIp ?? '0.0.0.0');
  }
  // Comma-separated, leftmost = original client, subsequent = proxies in order.
  const hops = xff
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  // We trust only `trustProxyHops` of the back of the list; the genuine
  // client IP is at index `hops.length - trustProxyHops - 1`.
  const idx = hops.length - trustProxyHops - 1;
  if (idx >= 0 && idx < hops.length && hops[idx] !== undefined) {
    return canonicalizeIp(hops[idx]);
  }
  // Fewer hops than configured -> the leftmost entry is the client.
  if (hops.length > 0 && hops[0] !== undefined) return canonicalizeIp(hops[0]);
  return canonicalizeIp(rawIp ?? '0.0.0.0');
}

/* ------------------------------------------------------------------ *
 * LRU — tiny bounded map (used for IP reputation cache, fail-soft nonce LRU)
 *
 * Uses Map insertion-order semantics (insertion marks MRU). Sub-millisecond
 * for typical sizes; chosen over linked-list-with-tail-head because eviction
 * is rare (size hits cap).
 * ------------------------------------------------------------------ */
export class LruMap<K, V> {
  private readonly store = new Map<K, V>();
  private readonly max: number;
  constructor(max: number) {
    if (max < 1) throw new Error('LruMap max must be >= 1');
    this.max = max;
  }
  get size(): number {
    return this.store.size;
  }
  get(key: K): V | undefined {
    const v = this.store.get(key);
    if (v === undefined) return undefined;
    // re-insert to mark MRU.
    this.store.delete(key);
    this.store.set(key, v);
    return v;
  }
  set(key: K, value: V): void {
    if (this.store.has(key)) this.store.delete(key);
    this.store.set(key, value);
    if (this.store.size > this.max) {
      const oldest = this.store.keys().next();
      if (!oldest.done) this.store.delete(oldest.value);
    }
  }
  has(key: K): boolean {
    return this.store.has(key);
  }
  delete(key: K): boolean {
    return this.store.delete(key);
  }
  clear(): void {
    this.store.clear();
  }
  entries(): IterableIterator<[K, V]> {
    return this.store.entries();
  }
}

/* ------------------------------------------------------------------ *
 * In-memory token bucket (fail-soft rate limiter fallback).
 *
 * Single-identity only; the orchestrator maintains one per identity in a
 * WeakMap-keyed-by-string. Cheap enough to be allocated per-identity.
 * ------------------------------------------------------------------ */
export interface MemoryBucketSnapshot {
  tokens: number;
  lastRefill: number;
}
export class MemoryTokenBucket {
  capacity: number;
  refillTokensPerSec: number;
  tokens: number;
  lastRefill: number;
  constructor(capacity: number, refillPerWindow: number, windowSec: number) {
    this.capacity = capacity;
    this.refillTokensPerSec = refillPerWindow / Math.max(1, windowSec);
    this.tokens = capacity;
    this.lastRefill = Date.now();
  }
  /** Tries to charge `cost` tokens. Returns the post-charge remaining tokens
   * (or -1 if rejected). Synchronized by the Node event loop's single thread. */
  charge(cost: number): number {
    const now = Date.now();
    const dtSec = (now - this.lastRefill) / 1000;
    if (dtSec > 0) {
      this.tokens = Math.min(this.capacity, this.tokens + dtSec * this.refillTokensPerSec);
      this.lastRefill = now;
    }
    if (this.tokens >= cost) {
      this.tokens -= cost;
      return this.tokens;
    }
    return -1;
  }
  snapshot(): MemoryBucketSnapshot {
    return { tokens: this.tokens, lastRefill: this.lastRefill };
  }
}

/* ------------------------------------------------------------------ *
 * Tiny CPU load sampler — used by the adaptive rate limiter sidecar.
 *
 * Returns a number in [0..1+]. We deliberately use process.cpuUsage() rather
 * than os.loadavg() because the latter is unix-only and coarse; cpuUsage is
 * cross-platform. Calculated as:
 *   load = (user+system over the last sample) / (sample window * cores).
 * We clamp at <=1 because users rarely want >100% load to mean "more credits
 * remaining"; we only need a binary high/low signal.
 * ------------------------------------------------------------------ */
export class CpuLoadSampler {
  private lastUser: number | null = null;
  private lastSystem: number | null = null;
  private lastAt = 0;
  private cores: number;
  private smoothed = 0;
  constructor(cores?: number) {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const os = require('node:os') as { cpus: () => unknown[] };
    this.cores = Math.max(1, cores ?? os.cpus().length);
  }
  /** Returns the exponentially-smoothed normalized load in [0,1]. */
  sample(): number {
    const cpu = process.cpuUsage();
    const now = performance.now();
    if (this.lastUser === null || this.lastSystem === null || this.lastAt === 0) {
      this.lastUser = cpu.user;
      this.lastSystem = cpu.system;
      this.lastAt = now;
      return 0;
    }
    const dtMs = now - this.lastAt;
    if (dtMs <= 0) return this.smoothed;
    // cpuUsage values are in *microseconds*. The ratio = used_us / (cores * dt_ms * 1000)
    // gives the fraction of CPU capacity utilized over the sampling window.
    const dtUs = Math.max(1, Math.round(dtMs)) * 1000;
    const duUser = cpu.user - this.lastUser;
    const duSystem = cpu.system - this.lastSystem;
    const totalUserUs = duUser < 0 ? 0 : duUser;
    const totalSystemUs = duSystem < 0 ? 0 : duSystem;
    const used = totalUserUs + totalSystemUs;
    const capacity = dtUs * this.cores;
    const ratio =
      capacity === 0
        ? 0
        : Math.min(1.0, used / capacity);
    // EWM smoothing to dampen spikes.
    this.smoothed = this.smoothed * 0.7 + ratio * 0.3;
    this.lastUser = cpu.user;
    this.lastSystem = cpu.system;
    this.lastAt = now;
    return this.smoothed;
  }
}

/* ------------------------------------------------------------------ *
 * Misc
 * ------------------------------------------------------------------ */
export function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}
export function nowMs(): number {
  return Date.now();
}
export function ceilToAtLeast1(n: number): number {
  return n < 1 ? 1 : Math.ceil(n);
}
