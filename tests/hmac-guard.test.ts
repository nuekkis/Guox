import { HmacGuard } from '../src/modules/hmac-guard';
import type { HmacOptions, RequestContext } from '../src/types';
import { ok as resultOk } from '../src/types';
import { createHmac } from 'node:crypto';

class MockRedisClient {
  keyPrefix = 'guox:';

  getKeyPrefix(): string { return this.keyPrefix; }

  key(suffix: string): string { return this.keyPrefix + suffix; }

  async evalsha() {
    return resultOk(['1']);
  }

  close(): void { /* noop */ }
}

function mockCtx(overrides?: Partial<RequestContext>): RequestContext {
  return {
    method: 'POST',
    path: '/api/webhook',
    clientIp: '1.2.3.4',
    userAgent: 'test',
    acceptLanguage: 'en',
    secChUa: '',
    jaFingerprint: '',
    rawBody: Buffer.from('{"event":"user.created"}', 'utf8'),
    identity: null,
    receivedAt: Date.now(),
    headers: {},
    requestId: 'req-1',
    parsedBody: { event: 'user.created' },
    parsedQuery: undefined,
    parsedParams: undefined,
    ...overrides,
  };
}

function signRequest(ctx: RequestContext, secret: string, keyId: string, nonce: string, opts?: Partial<HmacOptions>): Record<string, string> {
  const ts = String(Date.now());
  const stringToSign = ctx.method + '\n' + ctx.path + '\n' + ts + '\n' + nonce + '\n' + ctx.rawBody.toString('utf8');
  const sig = createHmac('sha256', secret).update(stringToSign, 'utf8').digest('hex');
  return {
    [(opts?.keyIdHeader ?? 'X-Key-Id').toLowerCase()]: keyId,
    [(opts?.signatureHeader ?? 'X-Signature').toLowerCase()]: sig,
    [(opts?.timestampHeader ?? 'X-Timestamp').toLowerCase()]: ts,
    [(opts?.nonceHeader ?? 'X-Nonce').toLowerCase()]: nonce,
  };
}

describe('HmacGuard', () => {
  const secret = Buffer.from('my-shared-secret-123');
  const secretResolver = async (keyId: string) => {
    if (keyId === 'key-1') return { keyId, secret };
    return null;
  };

  it('validates a correctly signed request', async () => {
    const guard = new HmacGuard(new MockRedisClient() as never, {
      secretResolver,
      signedRoutes: ['POST /api/webhook'],
    });
    const nonce = 'unique-nonce-123';
    const ctx = mockCtx({ headers: signRequest(mockCtx(), 'my-shared-secret-123', 'key-1', nonce) });
    const result = await guard.verify(ctx);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.valid).toBe(true);
    }
  });

  it('rejects missing signature headers', async () => {
    const guard = new HmacGuard(new MockRedisClient() as never, {
      secretResolver,
      signedRoutes: ['POST /api/webhook'],
    });
    const ctx = mockCtx({ headers: {} });
    const result = await guard.verify(ctx);
    expect(result.ok).toBe(false);
  });

  it('rejects invalid signature', async () => {
    const guard = new HmacGuard(new MockRedisClient() as never, {
      secretResolver,
      signedRoutes: ['POST /api/webhook'],
    });
    const ctx = mockCtx({
      headers: {
        'x-key-id': 'key-1',
        'x-signature': 'invalid-signature',
        'x-timestamp': String(Date.now()),
        'x-nonce': 'test-nonce',
      },
    });
    const result = await guard.verify(ctx);
    expect(result.ok).toBe(false);
  });

  it('rejects unknown key', async () => {
    const guard = new HmacGuard(new MockRedisClient() as never, {
      secretResolver,
      signedRoutes: ['POST /api/webhook'],
    });
    const ctx = mockCtx({
      headers: {
        'x-key-id': 'unknown-key',
        'x-signature': 'abc',
        'x-timestamp': String(Date.now()),
        'x-nonce': 'test-nonce',
      },
    });
    const result = await guard.verify(ctx);
    expect(result.ok).toBe(false);
  });

  it('skips unsigned routes', async () => {
    const guard = new HmacGuard(new MockRedisClient() as never, {
      secretResolver,
      signedRoutes: ['POST /api/sensitive'],
    });
    const ctx = mockCtx({ method: 'GET', path: '/api/public' });
    const result = await guard.verify(ctx);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.rejectKind).toBe('unsigned_route');
    }
  });

  it('rejects expired timestamp', async () => {
    const guard = new HmacGuard(new MockRedisClient() as never, {
      secretResolver,
      maxDriftMs: 100,
      signedRoutes: ['POST /api/webhook'],
    });
    const ctx = mockCtx({
      headers: {
        'x-key-id': 'key-1',
        'x-signature': 'abc',
        'x-timestamp': String(Date.now() - 10_000),
        'x-nonce': 'test-nonce',
      },
    });
    const result = await guard.verify(ctx);
    expect(result.ok).toBe(false);
  });
});
