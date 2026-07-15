/**
 * @guox / context.ts
 *
 * Builds the per-request `RequestContext` exactly once and threads it through
 * every module. Each guard reads from the same shared object — duplicated work
 * (e.g. hashing the User-Agent twice) is avoided by lazy memoization on the
 * context.
 */
import type { AdapterRequest, IdentityResolution, RequestContext, RateLimitOptions } from './types.js';
export declare function buildContext(req: AdapterRequest, baseOpts: {
    trustProxyHops: number;
}, identityStrategies: NonNullable<RateLimitOptions['identityStrategies']>, resolveIdentity?: RateLimitOptions['resolveIdentity']): RequestContext;
/**
 * Resolves identity lazily from the configured strategies. Used by the
 * rate-limit module's hot path — keeps the cold path of context bootstrap off
 * the critical path for anonymous requests when the rate limiter isn't
 * engaged (e.g. on a public health-check route).
 */
export declare function resolveIdentityOn(ctx: RequestContext, identityStrategies: NonNullable<RateLimitOptions['identityStrategies']>, customResolver?: RateLimitOptions['resolveIdentity']): IdentityResolution | null;
//# sourceMappingURL=context.d.ts.map