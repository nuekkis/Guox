import { RateLimiter } from '../src/modules/rate-limiter';
import type { RequestContext } from '../src/types';
import { ok as resultOk } from '../src/types';

class MockRedisClient {
  keyPrefix = 'guox:';

  getKeyPrefix(): string { return this.keyPrefix; }

  key(suffix: string): string { return this.keyPrefix + suffix; }

  async evalsha() {
    return resultOk(['1', '99', '0', '1', '100']);
  }

  close(): void { /* noop */ }
}

function mockCtx(overrides?: Partial<RequestContext>): RequestContext {
  return {
    method: 'GET',
    path: '/api/test',
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
    routeKey: undefined,
    ...overrides,
  };
}

describe('RateLimiter', () => {
  it('allows requests within limits', async () => {
    const limiter = new RateLimiter(new MockRedisClient() as never, {
      credits: 100,
      windowSeconds: 60,
    });
    const result = await limiter.decide(mockCtx(), () => ({ identity: 'user:1', strategy: 'ip' }));
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.allowed).toBe(true);
    }
  });

  it('matches cost rules', async () => {
    const limiter = new RateLimiter(new MockRedisClient() as never, {
      credits: 100,
      rules: [{ pattern: 'POST /login', cost: 20 }],
    });
    const ctx = mockCtx({ method: 'POST', path: '/login' });
    const result = await limiter.decide(ctx, () => ({ identity: 'user:1', strategy: 'ip' }));
    expect(result.ok).toBe(true);
  });

  it('handles anonymous requests', async () => {
    const limiter = new RateLimiter(new MockRedisClient() as never, {
      credits: 100,
    });
    const result = await limiter.decide(mockCtx(), () => null);
    expect(result.ok).toBe(true);
  });

  it('writes rate limit headers', () => {
    const limiter = new RateLimiter(new MockRedisClient() as never, {
      emitHeaders: true,
    });
    const headers: Array<[string, string | number]> = [];
    limiter.writeHeaders(
      (name, value) => { headers.push([name, value]); },
      { allowed: true, limit: 100, remaining: 85, retryAfter: 0, charged: 15 },
    );
    expect(headers.some(([n]) => n === 'X-RateLimit-Limit-Credits')).toBe(true);
    expect(headers.some(([n]) => n === 'X-RateLimit-Remaining-Credits')).toBe(true);
  });
});
