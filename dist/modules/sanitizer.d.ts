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
import type { RequestContext, SanitizerOptions, SecurityEvent } from '../types.js';
export interface SanitizerResult {
    readonly ok: boolean;
    readonly rejectKind: 'payload_malformed' | 'payload_too_deep' | 'prototype_pollution' | 'payload_oversize' | null;
    readonly cleanedBody?: unknown;
    readonly cleanedQuery?: unknown;
    readonly cleanedParams?: unknown;
    readonly inspectedKeys: number;
    readonly forbiddenStripped: number;
}
export declare class Sanitizer {
    private readonly forbiddenKeys;
    private readonly config;
    private excludes;
    constructor(opts?: SanitizerOptions);
    setExcludes(patterns: ReadonlyArray<string>): void;
    sanitize(ctx: RequestContext): SanitizerResult;
    buildRejectEvent(ctx: RequestContext, result: SanitizerResult): Omit<SecurityEvent, 'requestId' | 'at'> & {
        requestId?: string;
        at?: number;
    };
    private visit;
    private inspectedBudget;
    private isNonTraversal;
}
//# sourceMappingURL=sanitizer.d.ts.map