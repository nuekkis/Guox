# Guox — Architecture Blueprint

> Production-grade, enterprise Security Layer middleware for Node.js (Express & Fastify).
> Sub-millisecond overhead, Redis-backed atomic operations via Lua, fail-soft resiliency.

---

## 1. High-Level Topology

```
                ┌──────────────────────────────────────────────────────────┐
 Client ───────►│  Reverse Proxy (Cloudflare / Nginx / CloudFront)         │
                │  Injects JA3/JA4 headers, real client IP                 │
                └─────────────────────────────┬────────────────────────────┘
                                              │
                                              ▼
                ┌──────────────────────────────────────────────────────────┐
                │  Guox Middleware Chain  (Express / Fastify adapter)      │
                │                                                          │
                │  1. RequestContext bootstrap  (ip, ids, ts)             │
                │  2. PayloadSanitizer (proto pollution / depth / size)    │
                │  3. IP Reputation guard (fast block list)                │
                │  4. TLS/JA4 fingerprint bridge (spoofing detection)      │
                │  5. HMAC replay guard (signed endpoints only)            │
                │  6. Session fingerprint shield (authed endpoints)        │
                │  7. Cost-based rate limiter (sliding window)             │
                │  8. (optional) Schema drift validator                    │
                │  9. Audit/security event emission                       │
                └─────────────────────────────┬────────────────────────────┘
                                              │
                                              ▼
                ┌──────────────────────────────────────────────────────────┐
                │  Redis  (atomic Lua via EVALSHA)                         │
                │   - rate-limit sorted sets / token buckets               │
                │   - nonce de-dup hash (TTL)                              │
                │   - session fingerprint map / JWT blacklist              │
                │   - IP reputation set + per-IP violation counters        │
                └──────────────────────────────────────────────────────────┘
```

The chain is **ordered for cheapest-filter-first**: sanitization and reputation
checks run before any cryptographic or Redis round-trips, so abusive traffic is
dropped with minimal cost.

---

## 2. Request Flow

1. **Context bootstrap** — A single `RequestContext` object is built once per
   request and threaded through every module so each module only pays for the
   work it actually needs:
   - canonicalized client IP (honor `X-Forwarded-For` only under a trusted
     proxy hop count),
   - identity tuple `(apiKey | jwtSub | ipFallback)`,
   - method, path, raw body buffer reference,
   - parsed fingerprint (lazy),
   - received timestamp for replay window.

2. **Sanitizer** runs synchronously over `body/query/params`. It strips
   `__proto__`, `constructor`, `prototype`, enforces depth/size, and detects
   circular references. Rejects with `400` (malformed) or `413` (oversize).
   This is intentionally in-process (no Redis) so obviously-bad payloads never
   consume a Redis command.

3. **IP Reputation** — A `Set` of currently-blocked IPs is mirrored from Redis
   into an in-memory `Map<string, number>` keyed by `ip` with an `unblockAt`
   epoch. On violation, the per-IP counter increments via an atomic Redis Lua
   script; once it exceeds the configured threshold (`violationThreshold`,
   default 3 within `violationWindow`), the IP is added to the block set with a
   `blockTTL`. The fast path is a single `Map.has` lookup → sub-microsecond.

4. **JA4/TLS bridge** — Reads the configured proxy header, normalizes the
   `User-Agent` to a *family*, and consults a static `FamilyMap` of legitimate
   JA4 prefixes per browser family. Mismatches produce a `spoofed_bot` security
   event and (configurable) an immediate `403`.

5. **HMAC replay guard** (signed endpoints only):
   - Compute `|serverNow - X-Timestamp|`; reject if drift > `maxDriftSeconds`.
   - Run a Lua `setnx + pexpire` on `nonce:<hash>` for atomic de-dup with TTL.
   - Reconstruct `StringToSign = verb\npath\nts\nnonce\nrawBody`, recompute
     HMAC-SHA256 with the pre-shared secret, and compare with
     `crypto.timingSafeEqual` (after length equalization).

6. **Session fingerprint shield** (authed endpoints only):
   - Reconstruct the canonical fingerprint, SHA-256 it, and (timing-safe)
     compare to the `fp` claim baked into the JWT (or the value mapped in Redis
     by `session:<id> -> fpHash`).
   - On mismatch: revoke session in Redis, blacklist the JWT `jti`, emit a
     `session_hijack` security event, return `401`.

7. **Cost-based rate limiter**:
   - Resolve the endpoint's `cost` via the rule resolver.
   - Run a single Lua `EVALSHA` that atomically:
     1. ZADDs a member into a per-identity sorted set bounded by
        `(now - windowSeconds)` window-score,
     2. ZREMRANGEBYSCORE clears expired members,
     3. sums the costs in the surviving window,
     4. returns `[allowed, remaining, retryAfterSeconds]`.
   - On reject → `429` with `Retry-After` (seconds, ceiling) and the
     `X-RateLimit-*` headers. On allow → attaches headers downstream.

8. **Audit / Security event** — every module emits structured events through a
   single `EventSink` callback. Defaults to the Node `console` (JSON), can be
   swapped for any logger / SIEM transport.

---

## 3. Redis Key Schema

All keys are namespaced under a global prefix (default `guox:`) so the library
can share a Redis instance cleanly. Keys carry their own TTL where useful.

| Key pattern                                            | Type        | TTL        | Module                  |
|--------------------------------------------------------|-------------|------------|-------------------------|
| `guox:rl:{windowKey}:{identity}`                       | ZSET        | window + ε | Rate limiting           |
| `guox:rl:costs` (embedded in ZSET member prefix)       | (inline)    | n/a        | Rate limiting           |
| `guox:nonce:{sha256(nonce)}`                           | STRING      | drift      | HMAC replay             |
| `guox:revoked:jwt:{jti}`                               | STRING      | jwt exp    | Session shield          |
| `guox:session:{sessionId}`                             | HASH        | session    | Session shield (fpHash) |
| `guox:iprep:block:{ip}`                                | STRING      | blockTTL   | IP reputation           |
| `guox:iprep:viol:{ip}`                                 | STRING/incr | violWindow | IP reputation           |
| `guox:adapt:limit`                                     | STRING      | short      | Adaptive limiter factor  |

`windowKey` = the *first* second of the rolling window bucket; the ZSET member
encodes `"<reqId>:<cost>"` so the Lua script can sum cost without a second
round-trip. Members with score `< (now - windowSeconds)` are evicted every
request, keeping the ZSET bounded.

---

## 4. Resiliency Model (Circuit Breaker)

`RedisClient` wraps every `ioredis` call with a circuit breaker states machine:

```
        [ CLOSED ] ──failures >= threshold──► [ OPEN ]
              ▲                                    │
              │                          (after resetTtl)
              │                                    ▼
              └────── success ──── [ HALF_OPEN ] ──┘
                                    │
                              failure ─► back to OPEN
```

While OPEN, all Redis-backed guards take their **fail-soft** path:

| Module              | Redis-up behavior        | Redis-down (OPEN) behavior              |
|---------------------|--------------------------|-----------------------------------------|
| Rate limiting       | strict sliding window    | per-process in-memory refill-bucket     |
| Nonce de-dup        | strict setnx             | LRU in-memory nonce set (capped)        |
| Session shield      | Redis-backed revocation  | JWT blacklisting deferred locally       |
| IP reputation       | shared block list        | per-process block map only              |

A CRITICAL-level security event is emitted on each breaker state transition so
operators are alerted. The breaker never throws into the request path — it
resolves to a typed `Result.fail('circuit_open')` so middleware can branch
deterministically.

---

## 5. Performance Characteristics

- **Hot path**: pure sync JS work (sanitizer, fingerprint reconstruct, UA
  family map) — typically < 50µs per request.
- **Redis path**: exactly **one** `EVALSHA` round-trip per guard that needs it.
  Scripts are loaded once at boot (`SCRIPT LOAD`) and cached by SHA1, so steady
  state is `EVALSHA` only (no script body on the wire).
- **No `await` on unbounded work**: every async step is wrapped in
  `Promise.race([op, timeout])` with a configurable `redisCommandTimeoutMs`
  (default 80ms); a blown budget flips the breaker to OPEN rather than stalling
  the request.
- **Connection pooling**: a single warm `ioredis` cluster option is passed
  through; the library never opens additional connections on the request path.

---

## 6. Threat to Mitigation Matrix

| Threat                                         | Module(s)               | Response              |
|------------------------------------------------|-------------------------|-----------------------|
| API abuse / scrape bursts                       | 1 + IP reputation       | 429 + IP cool-down    |
| Replayed webhook / signed request              | 2                       | 403                   |
| Session/JWT theft + replay                     | 3                       | 401 + revocation      |
| `__proto__` / `constructor` pollution           | 4                       | 400 / sanitized       |
| NoDoS deep-nested JSON                          | 4                       | 413                   |
| Headless browser / TLS impersonation            | 5                       | flagged / 403         |
| Credential stuffing                            | 1 + IP reputation       | slow + block          |
| Credential stuffing Bursty attacker botnet    | Adaptive limiter        | threshold tightening |

---

## 7. Premium Additions (creative freedom)

1. **IP Reputation IP-set caching** — A per-process bounded LRU mirror of the
   Redis block set. The hot path is sync; only the cold path on a *new* block
   pushes the IP back to Redis (de-duplicated by a short "dirty" flag).
2. **Adaptive rate limiting** — A sidecar monitor samples `os.cpus().map(c =>
   c.load)`. When 1-min load average crosses `cpuHighWatermark` (default 70%),
   the Lua limiter is re-run with a tightened `effectiveCredits =
   baseCredits * (1 - cpuTightenFactor)` until load recovers. This prevents
   the global rate-limit from being useless when the server is the bottleneck.
3. **API schema drift detection** — Optional `schema: { validate: (ctx) =>
   ValidationResult }` on a route rule. Mismatches emit a `schema_drift`
   event (and optionally a `422`) and never throw user code; drift is reported
   as a metric, not a crash.

---
