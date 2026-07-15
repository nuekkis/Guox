"use strict";
/**
 * @guox / events.ts
 *
 * Single security event bus. The orchestrator passes the resolved sink from
 * the user's `GuoxOptions.onEvent`; defaults to a structured JSON logger on
 * stderr that is safe to ship to most SIEM agents.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.SecurityEventBus = void 0;
exports.defaultJsonConsoleSink = defaultJsonConsoleSink;
class SecurityEventBus {
    sink;
    defaultSink;
    constructor(sink) {
        this.sink = sink ?? null;
        this.defaultSink = defaultJsonConsoleSink;
    }
    emit(event) {
        try {
            if (this.sink)
                this.sink(event);
            else
                this.defaultSink(event);
        }
        catch {
            /* swallow — never break request flow from a logger's fault */
        }
    }
}
exports.SecurityEventBus = SecurityEventBus;
function defaultJsonConsoleSink(event) {
    const line = JSON.stringify({
        level: event.severity,
        evt: 'guox:' + event.kind,
        msg: event.message,
        rid: event.requestId,
        ts: event.at,
        ip: event.clientIp,
        m: event.method,
        path: event.path,
        identity: event.identity,
        ctx: event.context,
    });
    // Use process.stderr so JSON audit lines don't interleave with stdout data
    // e.g. when the app is piped to tooling. severity info|warn go to stdout,
    // severity error|critical go to stderr.
    if (event.severity === 'info' || event.severity === 'warn') {
        process.stdout.write(line + '\n');
    }
    else {
        process.stderr.write(line + '\n');
    }
}
//# sourceMappingURL=events.js.map