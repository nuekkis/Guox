# Guox

> Production-grade, enterprise Security Layer middleware for Node.js.
> Sub-millisecond overhead · Redis-backed atomic operations via Lua ·
> Fail-soft resiliency · One middleware to plug into Express **or** Fastify.

[![TypeScript](https://img.shields.io/badge/TypeScript-strict-blue)](#)
[![Node](https://img.shields.io/badge/Node.js-%3E%3D18-green)](#)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](#)

`guox` is a single middleware family that mitigates the entire spectrum
of advanced application-layer attacks:

| Module | Threat | Failure-mode |
| ----- | ----- | ------------ |
| 1 — Cost-based rate limiting | API abuse, scrape bursts | 429 with Retry-After |
| 2 — HMAC + replay guard | Tampered / replayed webhooks, IDOR replay | 401 / 403 |
| 3 — Session fingerprint shield | JWT / Session-ID theft & replay | 401 + revocation |
| 4 — Sanitizer + depth shield | Prototype pollution, NoDoS JSON | 400 / 413 |
| 5 — JA4/TLS bridge | Headless-browser impersonation | flagged / 403 |
| ✓ — IP reputation | Botnet recycling | IP cool-down block |
| ✓ — Adaptive limiter | Server overload + throttle | threshold tightening |
| ✓ — Schema drift | Silent API/contract regressions | flag / 422 |

All math happens in atomic Redis Lua scripts evaluated via `EVALSHA` —
one round-trip per module on the hot path. If Redis goes down, every module
fails gracefully without taking your app with it (fail-soft / in-memory fallback).

---

## Quickstart

### Express

```ts
import express from 'express';
import { createGuox, buildExpressAdapter } from 'guox';

const app = express();

// Capture the raw body so Guox can HMAC it on signed routes.
app.use(express.json({
  verify: (req, _res, buf) => { (req as any).__guoxRawBody = buf; },
}));

const guox = createGuox({
  redis: { url: 'redis://localhost:6379' },
  rateLimit: {
    windowSeconds: 60,
    credits: 100,
    rules: [
      { pattern: 'POST /login', cost: 15 },
      { pattern: 'POST /generate-pdf', cost: 40 },
      { pattern: 'GET /healthz', cost: 0 },
    ],
  },
  hmac: {
    signedRoutes: ['POST /webhooks/*'],
    secretResolver: (keyId) =>
      keyId === 'webhook-1'
        ? { keyId, secret: Buffer.from(process.env.WEBHOOK_SECRET!, 'utf8') }
        : null,
  },
  ja4: { onMismatch: 'block', jaHeader: 'x-ja4-fingerprint' },
  onEvent: (e) => console.log(JSON.stringify(e)),
});

app.use(buildExpressAdapter(guox).middleware());

app.post('/login', (req, res) => res.json({ ok: true }));
app.listen(3000);
```

### Fastify

```ts
import Fastify from 'fastify';
import { createGuox, buildFastifyAdapter } from 'guox';

const app = Fastify({ bodyLimit: 256 * 1024 });

// Stash the raw body where Guox can read it.
app.addContentTypeParser(
  'application/json',
  { parseAs: 'buffer' as const },
  (req, body, done) => {
    try {
      (req as any).__guoxRawBody = body as Buffer;
      done(null, JSON.parse((body as Buffer).toString('utf8')));
    } catch (e) { (done as any)(e); }
  },
);

const guox = createGuox({ /* same options as the Express example */ });
app.addHook('preHandler', buildFastifyAdapter(guox).preHandlerHook());

app.post('/login', async (_req, reply) => reply.send({ ok: true }));
app.listen({ port: 3000 });
```

---

## Cost model — why "cost" instead of request count

The default credit pool is `100` credits per `60` rolling seconds. The cost
of a request is configured per route; the sum of costs within the window must
stay below the pool. This kills many attack patterns that naive request-count
middlewares can't:

| Endpoint | Cost | Explanation |
| --- | --- | --- |
| `GET /public-data`     | 1  | Cheap read, costs almost nothing. |
| `POST /login`          | 15 | Expensive: bcrypt + email send — attacker burn 6x faster. |
| `POST /generate-pdf`   | 40 | CPU-heavy — burst-abuse only 2 in the window. |

Cost rules support `method prefix route` glob patterns (`POST /api/v1/users/**`,
`PATCH /orders/:id`). The earliest matching rule wins.

## HMAC — request integrity for webhooks

Signing keys are looked up by `X-Key-Id` through your provided resolver. The
canonical `StringToSign` is:

```
Verb + "\n" + Path + "\n" + X-Timestamp + "\n" + X-Nonce + "\n" + rawBody
```

The server recomputes HMAC-SHA256 with the matching pre-shared secret and
compares in constant time. The nonce is set atomically in Redis (Lua `SET ...
NX PX`) with a TTL equal to the configured drift window — a single
round-trip, no time-of-check time-of-use gap. If Redis is OPEN, the wrapper
degrades to a bounded in-memory LRU nonce set instead.

Surface to your webhook client: headers `X-Key-Id`, `X-Signature`,
`X-Timestamp`, `X-Nonce` (default names — overridable via `keyIdHeader`,
`signatureHeader`, `timestampHeader`, `nonceHeader`).

## Session fingerprint shield

At login, compute and store a fingerprint derived from the request
context:

```ts
const fp = guox.sessionShield!.fingerprintOf(ctx);
// Then either encrypt(fp) into the JWT's `fp` claim,
// or call awaits on `associate(sessionId, fp, ttlSec)`
```

The fingerprint is the SHA-256 of:

```
ipSubnet \x1f userAgent \x1f acceptLangHead \x1f secChUa
```

`ipSubnet` is `/24` for IPv4 or `/48` for IPv6 so moving from tower to tower
on a mobile device doesn't trigger a ReAuth — but flipping from
`37.142.51.0` to `83.18.4.0` does. Hard delimiters (`\x1f`) prevent the
canonicalization from accidentally collapsing two distinct fingerprints into
one.

## JA4 / TLS bridging

When fronted by Cloudflare/Nginx/AWS CloudFront with a JA4 plugin, you
configure the injected header name. Guox cross-checks the JA4 prefix
(plugin-stable across browser minor releases) against the UA's declared
browser family. A `python-requests/2.31.0` UA paired with a Chrome-like
header would otherwise fool your analytics; here it returns 403.

Per-route exclusions (`/healthz`, `/readyz`) avoid probing internal
liveness checks.

## IP reputation

After `3` security violations within `5 minutes`, the IP is blocked for
`10 minutes` — config via `ipReputation`. Blocks trigger any time a *known
attack signature* fires (rate-limited/hmac/prototype pollution/etc.). On
multi-process deployments, blocks are durable in Redis so a worker process
restart doesn't yield a free pass.

## Adaptive rate limiter

When `rateLimit.adaptive = true`, a sidecar CPU sampler runs in the same
event loop. If sampled load crosses `cpuHighWatermark` (default 0.7), the
Lua limiter is called with a tightened `tightenPct` (default 70% of
configured credits) until load recovers. This is *not* a generic DoS guard;
it's a selfish signal — your server asks the limiter "please slow down the
things that are hurting me" instead of dropping requests or OOMing.

## Schema drift

If you provide `schemaDrift.resolve = (ctx) => (body) => ({ valid: boolean, errors?: string[] }) | null`,
Guox runs the validator against the *post-sanitizer* body and either emits a
`schema_drift` event (default `flag`) or returns `422` (`block`). Useful as a
production tripwire for client/server contract regressions.

## Circuit breaker

Every Redis call goes through a per-instance breaker with:

- `failureThreshold: 5` (default)
- `failureWindowMs: 10_000`
- `resetTtlMs: 30_000`
- `halfOpenSuccesses: 2`
- `commandTimeoutMs: 80`

State transitions emit `circuit_breaker` events with severity
`info | warn | critical` per direction. CLOSED -> OPEN at `critical`,
OPEN -> HALF_OPEN -> CLOSED at `warn`/`info`. Hook them up to your alerting
pipeline via `onEvent`.

## Public API

| Symbol | Purpose |
| ------ | ------- |
| `createGuox(opts)` | Build a `Guox` orchestrator instance. |
| `guox.expressMiddleware()` | (Use `buildExpressAdapter(guox)` instead — see Quickstart.) |
| `guox.fastifyPreHandler()` | (Use `buildFastifyAdapter(guox)`.) |
| `guox.emit(event)` | Publish an *additional* security event (e.g. login failure → IP rep). |
| `guox.close()` | Disconnect the Redis pool. Use in graceful shutdown / tests. |
| `RATE_LIMIT_LUA` / `NONCE_CHECK_LUA` / `IP_REPUTATION_LUA` / `JWT_BLACKLIST_LUA` | The raw Lua scripts (audit them). |
| `DEFAULT_JA4_FAMILY_MAP` | The default JA4 prefix → browser family map. |
| `RedisClient`, `CpuLoadSampler`, `LruMap`, `MemoryTokenBucket` | Plumbing exposed for ops scripts. |

## Public API for testing

Each module is independently constructable:

```ts
import { Sanitizer, RateLimiter, IpReputation, Ja4Bridge, RedisClient } from 'guox';
```

Pass a mocked Redis-like (with `evalsha`, `eval`, `script('LOAD', ...)`, `on`,
`disconnect`, `status`) for unit tests.

## Logging & audit

Defaults to a structured-JSON sink on the process's stdout (info|warn) /
stderr (error|critical). Ship your own sink:

```ts
createGuox({
  onEvent: (e) => pino.child({}).warn(e),  // or Datadog, Loki, etc.
});
```

## License

Apache 2.0 — see `LICENSE`.
