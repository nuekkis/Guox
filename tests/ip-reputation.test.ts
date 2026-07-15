import { IpReputation } from '../src/modules/ip-reputation';
import type { RequestContext } from '../src/types';
import { ok as resultOk } from '../src/types';

class MockRedisClient {
  keyPrefix = 'guox:';

  getKeyPrefix(): string { return this.keyPrefix; }

  key(suffix: string): string { return this.keyPrefix + suffix; }

  async evalsha() {
    return resultOk(['0', '1']);
  }

  close(): void { /* noop */ }
}

function mockCtx(overrides?: Partial<RequestContext>): RequestContext {
  return {
    method: 'GET',
    path: '/',
    clientIp: '1.2.3.4',
    userAgent: 'test',
    acceptLanguage: 'en',
    secChUa: '',
    jaFingerprint: '',
    rawBody: Buffer.alloc(0),
    identity: null,
    receivedAt: Date.now(),
    headers: {},
    requestId: 'req-1',
    parsedBody: undefined,
    parsedQuery: undefined,
    parsedParams: undefined,
    ...overrides,
  };
}

describe('IpReputation', () => {
  it('allows non-blocked IPs', () => {
    const ipr = new IpReputation(new MockRedisClient() as never);
    const result = ipr.isBlocked(mockCtx());
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.blocked).toBe(false);
    }
  });

  it('records violations without false blocking', async () => {
    const ipr = new IpReputation(new MockRedisClient() as never, {
      violationThreshold: 5,
    });
    const result = await ipr.recordViolation(mockCtx(), 'rate_limited');
    expect(result.blocked).toBe(false);
  });

  it('snapshot returns counts', () => {
    const ipr = new IpReputation(new MockRedisClient() as never);
    const snap = ipr.snapshot();
    expect(typeof snap.blocked).toBe('number');
    expect(typeof snap.violations).toBe('number');
  });

  it('unblock clears entries', () => {
    const ipr = new IpReputation(new MockRedisClient() as never);
    expect(() => ipr.unblock('1.2.3.4')).not.toThrow();
  });

  it('dirty flag works', () => {
    const ipr = new IpReputation(new MockRedisClient() as never);
    expect(ipr.isDirty()).toBe(false);
    ipr.clearDirty();
    expect(ipr.isDirty()).toBe(false);
  });
});
