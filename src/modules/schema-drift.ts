/**
 * @guox / modules / schema-drift.ts — Premium Feature
 *
 * Automatic API payload schema drift detection.
 *
 * Production-deployed APIs accumulate silent drift: a field type changes in
 * the server-launched branch but not in the client app, or a client hits an
 * endpoint with a payload shape that *used* to be valid. These are not
 * crashes — request bodies parse fine — but they're silent reliability or
 * security bugs (e.g. an optional `email` field quietly becomes a CSV blob).
 *
 * This module is opt-in via `SchemaDriftOptions.resolve`. The integrator
 * provides a per-route validator; on mismatch we either:
 *   - flag it (default): emit a `schema_drift` event for the SIEM/metrics
 *     pipeline to surface in dashboards,
 *   - block the request (return `422 Unprocessable Entity`) for strict-mode
 *     endpoints.
 *
 * Why runtime validation rather than Zod schemas compiled in?
 *   - we deliberately stay JSON-schema-free at this layer to avoid a hard
 *     dependency on Zod/Ajv. Integrators can drop in any function with the
 *     shape `(body: unknown) => { valid, errors }`.
 *
 * Performance:
 *   - the validator runs **after** the sanitizer (cheap payload confirmed
 *     safe). The integrator-provided validator is the only sync work here,
 *     and the wrapper just dispatches.
 */

import type {
  RequestContext,
  SchemaDriftOptions,
  SecurityEvent,
} from '../types.js';

const DEFAULTS = {
  onDrift: 'flag' as const,
};

export interface SchemaDriftResult {
  readonly valid: boolean;
  readonly errors?: ReadonlyArray<string>;
  /** True if route is not schema-bound (no validator resolved). */
  readonly skipped: boolean;
}

export class SchemaDrift {
  private readonly config: Required<Pick<SchemaDriftOptions, 'onDrift'>> & {
    resolve?: NonNullable<SchemaDriftOptions['resolve']>;
  };

  constructor(opts?: SchemaDriftOptions) {
    this.config = {
      resolve: opts?.resolve,
      onDrift: opts?.onDrift ?? DEFAULTS.onDrift,
    };
  }

  /** Returns `valid: true` (skip) when route has no validator; otherwise runs
   *  the validator on the post-sanitizer body. */
  check(ctx: RequestContext): SchemaDriftResult {
    if (!this.config.resolve) {
      return { valid: true, skipped: true };
    }
    let validator;
    try {
      validator = this.config.resolve(ctx);
    } catch {
      // Validator resolution misconfigured: do not block (we don't know
      // whether this means "no validator" or "validator threw during load").
      return { valid: true, skipped: true };
    }
    if (!validator) {
      return { valid: true, skipped: true };
    }
    try {
      const r = validator(ctx.parsedBody);
      if (r.valid) return { valid: true, skipped: false };
      return {
        valid: false,
        errors: r.errors ?? [],
        skipped: false,
      };
    } catch (e) {
      return {
        valid: false,
        errors: [
          'validator threw: ' + (e instanceof Error ? e.message : String(e)),
        ],
        skipped: false,
      };
    }
  }

  buildEvent(ctx: RequestContext, result: SchemaDriftResult): Omit<
    SecurityEvent,
    'requestId' | 'at'
  > & { requestId?: string; at?: number } {
    return {
      kind: 'schema_drift',
      severity: this.config.onDrift === 'block' ? 'warn' : 'info',
      message: 'API payload does not match expected schema for route',
      clientIp: ctx.clientIp,
      path: ctx.path,
      method: ctx.method,
      context: {
        errors: result.errors,
      },
    };
  }

  /** Per-instance policy flag, exposed so the orchestrator doesn't need to
   *  replicate the same condition. */
  shouldBlock(): boolean {
    return this.config.onDrift === 'block';
  }
}
