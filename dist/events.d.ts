/**
 * @guox / events.ts
 *
 * Single security event bus. The orchestrator passes the resolved sink from
 * the user's `GuoxOptions.onEvent`; defaults to a structured JSON logger on
 * stderr that is safe to ship to most SIEM agents.
 */
import type { EventSink, SecurityEvent } from './types.js';
export declare class SecurityEventBus {
    private readonly sink;
    private readonly defaultSink;
    constructor(sink?: EventSink);
    emit(event: SecurityEvent): void;
}
export declare function defaultJsonConsoleSink(event: SecurityEvent): void;
//# sourceMappingURL=events.d.ts.map