/**
 * @guox / events.ts
 *
 * Single security event bus. The orchestrator passes the resolved sink from
 * the user's `GuoxOptions.onEvent`; defaults to a structured JSON logger on
 * stderr that is safe to ship to most SIEM agents.
 */

import type { EventSink, SecurityEvent } from './types.js';

export class SecurityEventBus {
  private readonly sink: EventSink | null;
  private readonly defaultSink: EventSink;

  constructor(sink?: EventSink) {
    this.sink = sink ?? null;
    this.defaultSink = defaultJsonConsoleSink;
  }

  emit(event: SecurityEvent): void {
    try {
      if (this.sink) this.sink(event);
      else this.defaultSink(event);
    } catch {
      /* swallow — never break request flow from a logger's fault */
    }
  }
}

export function defaultJsonConsoleSink(event: SecurityEvent): void {
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
  } else {
    process.stderr.write(line + '\n');
  }
}
