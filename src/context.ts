/**
 * @guox / context.ts
 *
 * Builds the per-request `RequestContext` exactly once and threads it through
 * every module. Each guard reads from the same shared object — duplicated work
 * (e.g. hashing the User-Agent twice) is avoided by lazy memoization on the
 * context.
 */

import type {
  AdapterRequest,
  IdentityResolution,
  RequestContext,
  RateLimitOptions,
} from './types.js';
import {
  freshRequestId,
  header,
  resolveClientIp,
} from './util.js';

export function buildContext(
  req: AdapterRequest,
  baseOpts: { trustProxyHops: number },
  identityStrategies: NonNullable<RateLimitOptions['identityStrategies']>,
  resolveIdentity?: RateLimitOptions['resolveIdentity'],
): RequestContext {
  const headers = req.headers;
  const clientIp = resolveClientIp(headers, req.ip, baseOpts.trustProxyHops);
  const userAgent = header(headers, 'user-agent').toLowerCase().replace(/\s+/g, ' ').trim();
  const acceptLanguage = header(headers, 'accept-language').toLowerCase().slice(0, 128);
  const secChUa = header(headers, 'sec-ch-ua').toLowerCase().slice(0, 256);
  const jaFingerprint =
    header(headers, 'x-ja4-fingerprint') || header(headers, 'cf-ja4-fingerprint') || '';

  // Raw body: prefer the framework-captured Buffer; if missing (e.g. a GET
  // request) use an empty Buffer so downstream code never has to null-check.
  const rawBody = req.rawBody ?? Buffer.alloc(0);

  // Identity resolution is lazy but, once resolved, memoized on the context.
  // We can't use a getter with mutable field, so we expose a public `identity`
  // slot lazily computed within the rate-limit module via `resolveIdentityOn`.
  const ctx: RequestContext = {
    method: req.method.toUpperCase(),
    path: req.path,
    clientIp,
    userAgent,
    acceptLanguage,
    secChUa,
    jaFingerprint,
    rawBody,
    identity: null,
    receivedAt: Date.now(),
    headers,
    requestId: freshRequestId(),
    parsedBody: req.body,
    parsedQuery: req.query,
    parsedParams: req.params,
  };

  // If we have a fast custom resolver, eagerly resolve.
  if (resolveIdentity) {
    try {
      const id = resolveIdentity(ctx);
      ctx.identity = finalizeIdentity(id, identityStrategies);
    } catch {
      ctx.identity = null;
    }
  }
  return ctx;
}

/**
 * Resolves identity lazily from the configured strategies. Used by the
 * rate-limit module's hot path — keeps the cold path of context bootstrap off
 * the critical path for anonymous requests when the rate limiter isn't
 * engaged (e.g. on a public health-check route).
 */
export function resolveIdentityOn(
  ctx: RequestContext,
  identityStrategies: NonNullable<RateLimitOptions['identityStrategies']>,
  customResolver?: RateLimitOptions['resolveIdentity'],
): IdentityResolution | null {
  if (ctx.identity) return ctx.identity;
  // Try strategies in order: api_key, jwt_sub, then ip.
  for (const strat of identityStrategies) {
    let resolved: IdentityResolution | null = null;
    if (strat === 'api_key') {
      const apiKey =
        header(ctx.headers, 'x-api-key') ||
        // Authorization: ApiKey sekret
        parseApiKeyFromAuthorization(header(ctx.headers, 'authorization'));
      if (apiKey) {
        resolved = {
          identity: sanitizedIdentity('apikey:' + apiKey) as IdentityResolution['identity'],
          strategy: 'api_key',
        };
      }
    } else if (strat === 'jwt_sub') {
      const bearer = parseBearer(header(ctx.headers, 'authorization'));
      if (bearer) {
        const sub = tryExtractJwtSub(bearer);
        if (sub) {
          resolved = {
            identity: sanitizedIdentity('jwt:' + sub) as IdentityResolution['identity'],
            strategy: 'jwt_sub',
          };
        }
      }
    } else if (strat === 'custom') {
      try {
        const r = customResolver ? customResolver(ctx) : null;
        if (r) resolved = r;
      } catch {
        resolved = null;
      }
    }
    if (resolved) {
      ctx.identity = resolved;
      return resolved;
    }
  }
  // Fallback to IP.
  const fallback: IdentityResolution = {
    identity: sanitizedIdentity('ip:' + ctx.clientIp) as IdentityResolution['identity'],
    strategy: 'ip',
  };
  ctx.identity = fallback;
  return fallback;
}

function finalizeIdentity(
  resolved: IdentityResolution | null,
  strategies: NonNullable<RateLimitOptions['identityStrategies']>,
): IdentityResolution | null {
  if (resolved) return resolved;
  // `custom` already tried above. Fall back to strategies.
  // Kept narrow for symmetry; covers edge cases where config omits 'ip'.
  if (strategies.length === 0) return null;
  return null;
}

/** Sanitizes identity for safe use as Redis ZSET suffix and audit log. */
function sanitizedIdentity(s: string): string {
  // Trim to 128 chars and purge control chars + colons (Redis-key safe).
  return s
    .slice(0, 128)
    .replace(/[^\x21-\x7e]/g, '')
    .replace(/[:\n\r\t]/g, '_');
}

function parseBearer(auth: string): string {
  const m = /^Bearer\s+(.+)$/i.exec(auth);
  return m && m[1] ? m[1].trim() : '';
}

function parseApiKeyFromAuthorization(auth: string): string {
  const m = /^(?:ApiKey|X-Api-Key|X-API-Key)\s+(.+)$/i.exec(auth);
  return m && m[1] ? m[1].trim() : '';
}

/** Decode a JWT `sub` claim without validating the signature — for identity
 * partitioning only. Validation, when required, is the application's job; we
 * never *trust* `sub` for security decisions, only for fair-share quota. */
function tryExtractJwtSub(bearer: string): string {
  const parts = bearer.split('.');
  if (parts.length !== 3) return '';
  const payload = parts[1] ?? '';
  if (payload.length > 32768) return ''; // defensive cap
  try {
    const padded = payload + '='.repeat((4 - (payload.length % 4)) % 4);
    const json = JSON.parse(
      Buffer.from(padded, 'base64url').toString('utf8'),
    ) as { sub?: unknown };
    if (typeof json.sub === 'string') return json.sub;
    return '';
  } catch {
    return '';
  }
}
