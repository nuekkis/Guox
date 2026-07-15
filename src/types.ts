/**
 * @guox / types.ts
 *
 * Core type surface for the Guox security layer. Every public symbol the
 * integrator touches originates here. Strict-mode TypeScript throughout.
 *
 * Design principles:
 *  - `unknown` over `any` everywhere possible.
 *  - Branded nominal types for security-sensitive scalars (Identity, Nonce).
 *  - Tagged unions for results so middleware branching is exhaustive-checked.
 */

import type { Readable } from 'node:stream';

/* ------------------------------------------------------------------ *
 * Branded primitives
 * ------------------------------------------------------------------ */

export type Brand<T, B extends string> = T & { readonly __brand: B };

/** Canonical identity used as the rate-limit partition key. */
export type Identity = Brand<string, 'Identity'>;

/** A client-provided high-entropy nonce, post-validation. */
export type NonceHash = Brand<string, 'NonceHash'>;

/** JA4/JA3 fingerprint token (e.g. `t13d1516h2_8daaf6152771_b0da82dd2788`). */
export type Ja4Fingerprint = Brand<string, 'Ja4Fingerprint'>;

/** Hashed device fingerprint (sha256 hex, 64 chars). */
export type FingerprintHash = Brand<string, 'FingerprintHash'>;

/* ------------------------------------------------------------------ *
 * Result type — exhaustive tagged union, never throws at boundaries
 * ------------------------------------------------------------------ */

export type Ok<T> = { readonly ok: true; readonly value: T };
export type Err<E extends SecurityError = SecurityError> = {
  readonly ok: false;
  readonly error: E;
};
export type Result<T, E extends SecurityError = SecurityError> =
  | Ok<T>
  | Err<E>;

export const ok = <T>(value: T): Ok<T> => ({ ok: true, value });
export const err = <E extends SecurityError>(error: E): Err<E> => ({
  ok: false,
  error,
});

/* ------------------------------------------------------------------ *
 * Security error vocabulary
 * ------------------------------------------------------------------ */

export type SecurityErrorKind =
  | 'circuit_open'
  | 'rate_limited'
  | 'replay_detected'
  | 'signature_invalid'
  | 'timestamp_drift'
  | 'session_revoked'
  | 'session_hijack'
  | 'fingerprint_mismatch'
  | 'payload_oversize'
  | 'payload_malformed'
  | 'payload_too_deep'
  | 'prototype_pollution'
  | 'ip_blocked'
  | 'tls_spoofing'
  | 'schema_drift'
  | 'misconfigured';

export interface SecurityError {
  readonly kind: SecurityErrorKind;
  readonly message: string;
  readonly statusCode: number;
  /** Free-form structured context, safe to ship to an audit log. */
  readonly context?: Readonly<Record<string, unknown>>;
}

/* ------------------------------------------------------------------ *
 * Redis / Circuit breaker
 * ------------------------------------------------------------------ */

export type BreakerState = 'closed' | 'open' | 'half_open';

export interface CircuitBreakerSnapshot {
  readonly state: BreakerState;
  readonly failures: number;
  readonly lastFailureAt: number | null;
  readonly openedAt: number | null;
}

export interface RedisOptions {
  /** ioredis connection URL. Mutually exclusive with `cluster`/`sentinel`. */
  readonly url?: string;
  /** A pre-built ioredis instance (recommended for shared pools). */
  readonly client?: unknown;
  /** Global key prefix. Default `guox:`. Must end with `:`. */
  readonly keyPrefix?: string;
  /** Command timeout (ms) after which a call is treated as a failure. */
  readonly commandTimeoutMs?: number;
  /** Failures in `failureWindowMs` required to open the breaker. */
  readonly failureThreshold?: number;
  readonly failureWindowMs?: number;
  /** Cool-down before OPEN -> HALF_OPEN probe. */
  readonly resetTtlMs?: number;
  /** Consecutive successes in HALF_OPEN required to close. */
  readonly halfOpenSuccesses?: number;
}

/* ------------------------------------------------------------------ *
 * Identity / RequestContext
 * ------------------------------------------------------------------ */

export type IdentityStrategy =
  | 'api_key'
  | 'jwt_sub'
  | 'ip'
  /** Resolve identity with a custom function. Must never throw. */
  | 'custom';

export interface IdentityResolution {
  readonly identity: Identity;
  /** One of the strategies that produced this identity, for audit. */
  readonly strategy: IdentityStrategy | 'custom';
}

export interface RequestContext {
  /** Raw HTTP method, uppercased. */
  readonly method: string;
  /** URL pathname, query stripped. */
  readonly path: string;
  /** Canonicalized client IP (after trust-proxy resolution). */
  readonly clientIp: string;
  /** Lowercased, trimmed User-Agent (or empty string). */
  readonly userAgent: string;
  /** Normalized Accept-Language (or empty string). */
  readonly acceptLanguage: string;
  /** Sec-CH-UA header (`Sec-CH-UA`), normalized, or empty string. */
  readonly secChUa: string;
  /** JA4 / JA3 fingerprint as passed by the proxy (or empty string). */
  readonly jaFingerprint: string;
  /** Raw body as captured upstream. May be empty Buffer for GET. */
  readonly rawBody: Buffer;
  /** Lazily-populated identity. `null` until resolved. */
  identity: IdentityResolution | null;
  /** Server-received timestamp (ms epoch) for replay window. */
  readonly receivedAt: number;
  /** All request headers as a plain lowercased-key object. */
  readonly headers: Readonly<Record<string, string | string[] | undefined>>;
  /** A per-request unique id for log correlation. */
  readonly requestId: string;
  /** Out-band: any parsed body the framework already produced. */
  parsedBody?: unknown;
  /** Out-band: parsed query. */
  parsedQuery?: unknown;
  /** Out-band: parsed params. */
  parsedParams?: unknown;
  /** Optional assigned route name (e.g. `POST /login`), for cost routing. */
  routeKey?: string;
}

/* ------------------------------------------------------------------ *
 * Module 1 — Cost-based rate limiting
 * ------------------------------------------------------------------ */

export interface CostRule {
  /** Glob matcher (glob-to-regexp compiled) or literal path. */
  readonly pattern: string;
  readonly method?: string;
  readonly cost: number;
  /** Per-route override of window length / credit pool. */
  readonly windowSeconds?: number;
  readonly credits?: number;
}

export interface RateLimitDecision {
  readonly allowed: boolean;
  readonly limit: number;
  readonly remaining: number;
  /** Seconds until enough credit regenerates to retry. 0 if allowed. */
  readonly retryAfter: number;
  /** The cost actually charged. 0 if not allowed. */
  readonly charged: number;
}

export interface RateLimitOptions {
  /** Default rolling window (seconds). Default 60. */
  readonly windowSeconds?: number;
  /** Default credit pool per identity per window. Default 100. */
  readonly credits?: number;
  /** Per-route cost rules; first match wins. */
  readonly rules?: ReadonlyArray<CostRule>;
  /** Strategy for resolving identity. Default `['api_key','jwt_sub','ip']`. */
  readonly identityStrategies?: ReadonlyArray<IdentityStrategy>;
  /** Custom identity resolver; required iff `'custom'` is in strategies. */
  readonly resolveIdentity?: (ctx: RequestContext) => IdentityResolution | null;
  /** Sentinel returned when limiter is unavailable (Redis OPEN). Default allow. */
  readonly failSoft?: 'allow' | 'deny';
  /** Header toggle. Default true. */
  readonly emitHeaders?: boolean;
  /** When server CPU is high, multipler on `credits` (must be in (0,1]). */
  readonly cpuTightenFactor?: number;
  /** Enable adaptive tightening based on CPU. */
  readonly adaptive?: boolean;
}

/* ------------------------------------------------------------------ *
 * Module 2 — HMAC replay protection
 * ------------------------------------------------------------------ */

export interface HmacClientSecret {
  /** Stable key id; lets clients rotate secrets. */
  readonly keyId: string;
  /** The pre-shared secret as a Buffer (UTF-8 of the raw secret). */
  readonly secret: Buffer;
}

export type SecretResolver = (
  keyId: string,
) => Promise<HmacClientSecret | null> | HmacClientSecret | null;

export interface HmacOptions {
  /** Header carrying the key id (client selects secret). Default `X-Key-Id`. */
  readonly keyIdHeader?: string;
  readonly signatureHeader?: string;
  readonly timestampHeader?: string;
  readonly nonceHeader?: string;
  /** Max accepted |serverTime - X-Timestamp| ms. Default 5000. */
  readonly maxDriftMs?: number;
  /** TTL of nonce entries in Redis (ms). Default maxDriftMs * 1.5. */
  readonly nonceTtlMs?: number;
  /** Resolve the secret for the supplied key id. */
  readonly secretResolver: SecretResolver;
  /** Routes that require signing; glob patterns. Empty = sign everything. */
  readonly signedRoutes?: ReadonlyArray<string>;
  /** Whether to also validate response bodies. Default false. */
  readonly signatureEncoding?: 'hex' | 'base64';
}

/* ------------------------------------------------------------------ *
 * Module 3 — Session fingerprint shield
 * ------------------------------------------------------------------ */

export interface SessionClaims {
  readonly jti?: string;
  readonly sub?: string;
  readonly sessionId?: string;
  /** Embedded encrypted `fp` claim if JWT-based. */
  readonly fp?: string;
  readonly exp?: number;
}

export interface FingerprintShieldOptions {
  /** Extract a SessionClaims from the context. */
  readonly extractClaims: (ctx: RequestContext) => SessionClaims | null;
  /** Decrypt the embedded `fp` claim back to the canonical hash. */
  readonly decryptFpClaim?: (
    encrypted: string,
  ) => Promise<FingerprintHash | null> | FingerprintHash | null;
  /** Encrypt the freshly-computed hash for embedding into the JWT. */
  readonly encryptFpClaim?: (
    hash: FingerprintHash,
  ) => Promise<string> | string;
  /** If JWT-based, where to write the `fp` claim at login time. */
  readonly fpClaimName?: string;
  /** On mismatch -> 'block' returns 401; 'flag' logs but continues. */
  readonly onMismatch?: 'block' | 'flag';
}

/* ------------------------------------------------------------------ *
 * Module 4 — Sanitizer
 * ------------------------------------------------------------------ */

export interface SanitizerOptions {
  readonly maxDepth?: number;
  readonly maxKeys?: number;
  readonly maxBytes?: number;
  /** Custom forbidden key matches (joined with the built-ins). */
  readonly forbiddenKeys?: ReadonlyArray<string>;
  /** Action when a forbidden key is found. Default 'drop_key'. */
  readonly forbiddenAction?: 'drop_key' | 'drop_request';
  /** Whether to also resolve circular refs (true) or reject them (false). */
  readonly onCircular?: 'drop_request' | 'break_link';
}

/* ------------------------------------------------------------------ *
 * Module 5 — JA4/TLS bridge
 * ------------------------------------------------------------------ */

export type BrowserFamily =
  | 'chrome'
  | 'firefox'
  | 'safari'
  | 'edge'
  | 'other';

/** Maps a JA4 prefix / family triplet to expected browser families. */
export interface Ja4FamilyMap {
  /** Each entry: ja4 prefix -> array of families it is consistent with. */
  readonly [ja4Prefix: string]: ReadonlyArray<BrowserFamily>;
}

export interface Ja4Options {
  readonly jaHeader?: string;
  /** Strict ordering: extra proxies' headers tried in sequence. */
  readonly alternateJaHeaders?: ReadonlyArray<string>;
  readonly familyMap?: Ja4FamilyMap;
  /** Action on mismatch. Default 'block'. */
  readonly onMismatch?: 'block' | 'flag';
  /** Patterns of paths exempt from JA4 enforcement (e.g. health checks). */
  readonly excludeRoutes?: ReadonlyArray<string>;
}

/* ------------------------------------------------------------------ *
 * Premium — IP reputation / schema drift
 * ------------------------------------------------------------------ */

export interface IpReputationOptions {
  readonly violationThreshold?: number;
  readonly violationWindowSeconds?: number;
  readonly blockTtlSeconds?: number;
  /** In-memory LRU cap. */
  readonly memoryCacheSize?: number;
  /** Which security events count as a reputational violation. */
  readonly violationEvents?: ReadonlyArray<SecurityEvent['kind']>;
}

export interface SchemaDriftOptions {
  /** Returns null if route is not schema-bound, else a validator. */
  readonly resolve?: (ctx: RequestContext) =>
    | ((body: unknown) => SchemaValidationResult)
    | null;
  readonly onDrift?: 'block' | 'flag';
}

export interface SchemaValidationResult {
  readonly valid: boolean;
  readonly errors?: ReadonlyArray<string>;
}

/* ------------------------------------------------------------------ *
 * Security event sink
 * ------------------------------------------------------------------ */

export type SecurityEventKind =
  | 'circuit_breaker'
  | 'rate_limited'
  | 'replay_detected'
  | 'signature_invalid'
  | 'timestamp_drift'
  | 'session_hijack'
  | 'session_revoked'
  | 'fingerprint_mismatch'
  | 'prototype_pollution'
  | 'payload_too_deep'
  | 'ip_blocked'
  | 'tls_spoofing'
  | 'schema_drift';

export interface SecurityEvent {
  readonly kind: SecurityEventKind;
  readonly severity: 'info' | 'warn' | 'error' | 'critical';
  readonly requestId: string;
  readonly at: number;
  readonly identity?: IdentityResolution | null;
  readonly clientIp?: string;
  readonly path?: string;
  readonly method?: string;
  readonly message: string;
  readonly context?: Readonly<Record<string, unknown>>;
}

export type EventSink = (event: SecurityEvent) => void;

/* ------------------------------------------------------------------ *
 * Top-level Guox config
 * ------------------------------------------------------------------ */

export interface GuoxOptions {
  readonly redis?: RedisOptions;
  readonly rateLimit?: RateLimitOptions;
  readonly hmac?: HmacOptions;
  readonly sessionShield?: FingerprintShieldOptions;
  readonly sanitizer?: SanitizerOptions;
  readonly ja4?: Ja4Options;
  readonly ipReputation?: IpReputationOptions;
  readonly schemaDrift?: SchemaDriftOptions;
  /** Default event sink. Emits structured JSON to console if omitted. */
  readonly onEvent?: EventSink;
  /** Honor up to N proxy hops for client IP resolution. Default 1. */
  readonly trustProxyHops?: number;
  /** Disable a guard entirely without affecting others. */
  readonly disabled?: ReadonlyArray<
    | 'rateLimit'
    | 'hmac'
    | 'sessionShield'
    | 'sanitizer'
    | 'ja4'
    | 'ipReputation'
    | 'schemaDrift'
  >;
}

/* ------------------------------------------------------------------ *
 * Adapter-agnostic request/response abstraction
 * ------------------------------------------------------------------ */

/**
 * Adapters (Express, Fastify) project their native request/response onto this
 * shape. The core never touches framework types, guaranteeing adapter parity.
 */
export interface AdapterRequest {
  readonly method: string;
  readonly path: string;
  readonly url: string;
  readonly headers: Readonly<Record<string, string | string[] | undefined>>;
  readonly rawBody?: Buffer;
  readonly body?: unknown;
  readonly query?: unknown;
  readonly params?: unknown;
  readonly ip?: string;
  readonly stream?: Readable;
}

export interface AdapterResponse {
  readonly setHeader: (name: string, value: string | number) => void;
  readonly setStatus: (code: number) => void;
  readonly sendJson: (body: unknown) => void;
  readonly end: () => void;
}

export type Next = (err?: unknown) => void;

export interface MiddlewareContext {
  readonly req: AdapterRequest;
  readonly res: AdapterResponse;
  readonly next: Next;
  readonly ctx: RequestContext;
}

/* ------------------------------------------------------------------ *
 * Misc helpers — brand constructors exported for internal reuse
 * ------------------------------------------------------------------ */

export const Identity = (s: string): Identity =>
  s as unknown as Identity;
export const NonceHash = (s: string): NonceHash =>
  s as unknown as NonceHash;
export const Ja4Fingerprint = (s: string): Ja4Fingerprint =>
  s as unknown as Ja4Fingerprint;
export const FingerprintHash = (s: string): FingerprintHash =>
  s as unknown as FingerprintHash;
