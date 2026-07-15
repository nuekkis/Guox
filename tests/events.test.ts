import { SecurityEventBus, defaultJsonConsoleSink } from '../src/events';
import type { SecurityEvent } from '../src/types';

describe('SecurityEventBus', () => {
  it('emits to custom sink', () => {
    const events: SecurityEvent[] = [];
    const bus = new SecurityEventBus((e) => { events.push(e); });
    bus.emit({
      kind: 'rate_limited',
      severity: 'warn',
      requestId: 'req-1',
      at: Date.now(),
      message: 'test event',
    });
    expect(events).toHaveLength(1);
    expect(events[0]!.kind).toBe('rate_limited');
  });

  it('defaults to console sink when no sink provided', () => {
    const bus = new SecurityEventBus();
    const stdoutWrite = jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
    const stderrWrite = jest.spyOn(process.stderr, 'write').mockImplementation(() => true);

    bus.emit({
      kind: 'rate_limited',
      severity: 'warn',
      requestId: 'req-1',
      at: Date.now(),
      message: 'test',
    });

    expect(stdoutWrite).toHaveBeenCalled();
    stdoutWrite.mockRestore();
    stderrWrite.mockRestore();
  });

  it('emits error severity to stderr', () => {
    const bus = new SecurityEventBus();
    const stderrWrite = jest.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const stdoutWrite = jest.spyOn(process.stdout, 'write').mockImplementation(() => true);

    bus.emit({
      kind: 'circuit_breaker',
      severity: 'error',
      requestId: 'req-1',
      at: Date.now(),
      message: 'test error',
    });

    expect(stderrWrite).toHaveBeenCalled();
    expect(stdoutWrite).not.toHaveBeenCalled();
    stderrWrite.mockRestore();
    stdoutWrite.mockRestore();
  });

  it('swallows sink errors', () => {
    const bus = new SecurityEventBus(() => { throw new Error('sink error'); });
    expect(() => {
      bus.emit({
        kind: 'rate_limited',
        severity: 'warn',
        requestId: 'req-1',
        at: Date.now(),
        message: 'test',
      });
    }).not.toThrow();
  });
});

describe('defaultJsonConsoleSink', () => {
  it('writes JSON to stdout', () => {
    const write = jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
    defaultJsonConsoleSink({
      kind: 'rate_limited',
      severity: 'info',
      requestId: 'req-1',
      at: 1000,
      message: 'test',
    });
    expect(write).toHaveBeenCalledWith(expect.stringContaining('guox:rate_limited'));
    write.mockRestore();
  });
});
