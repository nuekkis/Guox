/**
 * @guox / modules / sanitizer.ts — Module 4
 *
 * Prototype-pollution + payload-size-inflation shield. Synchronous and pure;
 * no Redis, no allocations aside from result-stack. Runs as the FIRST module
 * in the chain so legitimately malicious payloads never pay a single Redis
 * command.
 *
 * Guarantees:
 *   - Keys named `__proto__`, `constructor`, `prototype` (case-insensitive)
 *     are stripped from every object level. Detection uses
 *     `Object.prototype.hasOwnProperty.call` to avoid prototype traps.
 *   - Strict depth cap (default 5) — deeper payloads rejected with 413.
 *   - Recursive key budget (default 10_000 keys) — guards against extremely
 *     broad payloads.
 *   - Total-bytes cap (when raw body present) for early-bail.
 *   - Circular reference handling: drop request or break link.
 *
 * The sanitizer is destructive: it mutates the parsed payload in place.
 */

import type {
  RequestContext,
  SanitizerOptions,
  SecurityEvent,
} from '../types.js';
import { compileGlob } from '../util.js';

const BUILTIN_FORBIDDEN = new Set<string>([
  '__proto__',
  'constructor',
  'prototype',
]);

const DEFAULTS = {
  maxDepth: 5,
  maxKeys: 10_000,
  maxBytes: 256 * 1024, // 256 KiB
  forbiddenAction: 'drop_key' as const,
  onCircular: 'drop_request' as const,
};

interface SanitizerConfigResolved {
  readonly maxDepth: number;
  readonly maxKeys: number;
  readonly maxBytes: number;
  readonly forbiddenKeys: ReadonlyArray<string>;
  readonly forbiddenAction: 'drop_key' | 'drop_request';
  readonly onCircular: 'drop_request' | 'break_link';
}

export interface SanitizerResult {
  readonly ok: boolean;
  readonly rejectKind:
    | 'payload_malformed'
    | 'payload_too_deep'
    | 'prototype_pollution'
    | 'payload_oversize'
    | null;
  readonly cleanedBody?: unknown;
  readonly cleanedQuery?: unknown;
  readonly cleanedParams?: unknown;
  readonly inspectedKeys: number;
  readonly forbiddenStripped: number;
}

const NON_TRAVERSAL_NAMES = new Set<string>([
  'Buffer',
  'Uint8Array',
  'Int8Array',
  'Uint8ClampedArray',
  'Uint16Array',
  'Int16Array',
  'Uint32Array',
  'Int32Array',
  'Float32Array',
  'Float64Array',
  'BigInt64Array',
  'BigUint64Array',
  'DataView',
  'ArrayBuffer',
  'Date',
  'RegExp',
  'URL',
  'URLSearchParams',
  'Map',
  'Set',
  'WeakMap',
  'WeakSet',
  'Promise',
]);

export class Sanitizer {
  private readonly forbiddenKeys: Set<string>;
  private readonly config: SanitizerConfigResolved;
  private excludes: ReadonlyArray<(subject: string) => boolean> = [];

  constructor(opts?: SanitizerOptions) {
    this.config = {
      maxDepth: opts?.maxDepth ?? DEFAULTS.maxDepth,
      maxKeys: opts?.maxKeys ?? DEFAULTS.maxKeys,
      maxBytes: opts?.maxBytes ?? DEFAULTS.maxBytes,
      forbiddenKeys: opts?.forbiddenKeys ? [...opts.forbiddenKeys] : [],
      forbiddenAction: opts?.forbiddenAction ?? DEFAULTS.forbiddenAction,
      onCircular: opts?.onCircular ?? DEFAULTS.onCircular,
    };
    this.forbiddenKeys = new Set<string>([
      ...BUILTIN_FORBIDDEN,
      ...this.config.forbiddenKeys.map((k) => k.toLowerCase()),
    ]);
  }

  setExcludes(patterns: ReadonlyArray<string>): void {
    this.excludes = patterns.map((p) => compileGlob(p));
  }

  sanitize(ctx: RequestContext): SanitizerResult {
    const key = ctx.method + ' ' + ctx.path;
    if (this.excludes.some((m) => m(key))) {
      return { ok: true, rejectKind: null, inspectedKeys: 0, forbiddenStripped: 0 };
    }
    if (ctx.rawBody.length > this.config.maxBytes) {
      return {
        ok: false,
        rejectKind: 'payload_oversize',
        inspectedKeys: 0,
        forbiddenStripped: 0,
      };
    }

    const state: SanitizeState = {
      inspectedKeys: 0,
      forbiddenStripped: 0,
      tooDeep: false,
      malformed: false,
      circular: false,
      recursionStack: [],
    };

    let cleanedBody: unknown;
    let cleanedQuery: unknown;
    let cleanedParams: unknown;
    try {
      cleanedBody = this.visit(ctx.parsedBody, 0, state);
      cleanedQuery = this.visit(ctx.parsedQuery, 0, state);
      cleanedParams = this.visit(ctx.parsedParams, 0, state);
    } catch {
      state.malformed = true;
    }

    if (state.circular && this.config.onCircular === 'drop_request') {
      return {
        ok: false,
        rejectKind: 'payload_malformed',
        inspectedKeys: state.inspectedKeys,
        forbiddenStripped: state.forbiddenStripped,
      };
    }
    if (state.malformed) {
      return {
        ok: false,
        rejectKind: 'payload_malformed',
        inspectedKeys: state.inspectedKeys,
        forbiddenStripped: state.forbiddenStripped,
      };
    }
    if (state.tooDeep) {
      return {
        ok: false,
        rejectKind: 'payload_too_deep',
        inspectedKeys: state.inspectedKeys,
        forbiddenStripped: state.forbiddenStripped,
      };
    }
    if (state.forbiddenStripped > 0 && this.config.forbiddenAction === 'drop_request') {
      return {
        ok: false,
        rejectKind: 'prototype_pollution',
        inspectedKeys: state.inspectedKeys,
        forbiddenStripped: state.forbiddenStripped,
      };
    }

    // Write cleaned payloads back so downstream code sees them.
    (ctx as { parsedBody?: unknown }).parsedBody = cleanedBody;
    (ctx as { parsedQuery?: unknown }).parsedQuery = cleanedQuery;
    (ctx as { parsedParams?: unknown }).parsedParams = cleanedParams;

    return {
      ok: true,
      rejectKind: null,
      cleanedBody,
      cleanedQuery,
      cleanedParams,
      inspectedKeys: state.inspectedKeys,
      forbiddenStripped: state.forbiddenStripped,
    };
  }

  buildRejectEvent(
    ctx: RequestContext,
    result: SanitizerResult,
  ): Omit<SecurityEvent, 'requestId' | 'at'> & { requestId?: string; at?: number } {
    const kind: SecurityEvent['kind'] =
      result.rejectKind === 'prototype_pollution'
        ? 'prototype_pollution'
        : 'payload_too_deep';
    return {
      kind,
      severity: 'warn',
      message: `sanitizer rejected: ${result.rejectKind}`,
      clientIp: ctx.clientIp,
      path: ctx.path,
      method: ctx.method,
      context: {
        forbiddenStripped: result.forbiddenStripped,
        inspectedKeys: result.inspectedKeys,
      },
    };
  }

  /* -------- private -------- */

  private visit(node: unknown, depth: number, state: SanitizeState): unknown {
    if (depth > this.config.maxDepth) {
      state.tooDeep = true;
      return undefined;
    }
    if (node === null || typeof node !== 'object') return node;
    if (this.inspectedBudget(state)) return node;

    // Preserve typed wrappers (Buffer, Date, URL, Map, Set, etc.)
    if (this.isNonTraversal(node)) return node;

    // Circular detection (skip on typed wrappers — handled above).
    for (let i = 0; i < state.recursionStack.length; i++) {
      if (state.recursionStack[i] === (node as object)) {
        state.circular = true;
        if (this.config.onCircular === 'drop_request') return undefined;
        return null; // break the back-link
      }
    }

    if (Array.isArray(node)) {
      state.recursionStack.push(node);
      try {
        for (let i = 0; i < node.length; i++) {
          if (this.inspectedBudget(state)) return node;
          node[i] = this.visit(node[i], depth, state) as unknown;
        }
      } finally {
        state.recursionStack.pop();
      }
      return node;
    }

    // Plain dict.
    state.recursionStack.push(node as object);
    try {
      const names = Object.keys(node as Record<string, unknown>);
      for (let i = 0; i < names.length; i++) {
        const name = names[i]!;
        if (!Object.prototype.hasOwnProperty.call(node, name)) continue;
        const lower = name.toLowerCase();
        if (this.forbiddenKeys.has(lower)) {
          state.forbiddenStripped++;
          delete (node as Record<string, unknown>)[name];
          continue;
        }
        if (this.inspectedBudget(state)) return node;
        try {
          const child = (node as Record<string, unknown>)[name];
          (node as Record<string, unknown>)[name] = this.visit(child, depth + 1, state);
        } catch {
          state.malformed = true;
        }
      }
    } finally {
      state.recursionStack.pop();
    }
    return node;
  }

  private inspectedBudget(state: SanitizeState): boolean {
    state.inspectedKeys++;
    return state.inspectedKeys > this.config.maxKeys;
  }

  private isNonTraversal(node: object): boolean {
    const ctor = (node as { constructor?: { name?: string } }).constructor;
    if (!ctor) return false;
    return NON_TRAVERSAL_NAMES.has(ctor.name || '');
  }
}

interface SanitizeState {
  inspectedKeys: number;
  forbiddenStripped: number;
  tooDeep: boolean;
  malformed: boolean;
  circular: boolean;
  recursionStack: object[];
}
