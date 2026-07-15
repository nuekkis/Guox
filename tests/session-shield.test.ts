import { SessionShield } from '../src/modules/session-shield';
import type { FingerprintShieldOptions, RequestContext } from '../src/types';
import { ok as resultOk } from '../src/types';

class MockRedisClient {
  keyPrefix = 'guox:';
  private store = new Map<string, string>();

  getKeyPrefix(): string { return this.keyPrefix; }

  key(suffix: string): string { return this.keyPrefix + suffix; }

  async evalsha(script: string, keys: string[], args: (string | number)[]): Promise<ReturnType<typeof resultOk>> {
    if (script.includes('HGET') || script.includes('hget')) {
      const fp = this.store.get(keys[0] ?? '');
      if (fp) return resultOk(fp);
      return resultOk(''); // empty = not found
    }
    return resultOk(['1']);
  }

  close(): void { /* noop */ }
}

function mockCtx(overrides?: Partial<RequestContext>): RequestContext {
  return {
    method: 'GET',
    path: '/api/profile',
    clientIp: '192.168.1.42',
    userAgent: 'Mozilla/5.0 Chrome/120',
    acceptLanguage: 'en-US,en;q=0.9',
    secChUa: '"Chromium";v="120", "Google Chrome";v="120"',
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

describe('SessionShield', () => {
  const extractClaims = (ctx: RequestContext) => {
    const auth = ctx.headers['authorization'] as string | undefined;
    if (!auth) return null;
    return { sub: 'user-1', jti: 'jti-abc', sessionId: 'sess-123', exp: Date.now() / 1000 + 3600 };
  };

  const opts: FingerprintShieldOptions = {
    extractClaims,
    onMismatch: 'block',
  };

  it('skips when no claims extracted', async () => {
    const shield = new SessionShield(new MockRedisClient() as never, opts);
    const ctx = mockCtx({ headers: {} });
    const result = await shield.verify(ctx);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.reason).toBe('missing_claims');
    }
  });

  it('returns matched on first request (no stored fp)', async () => {
    const shield = new SessionShield(new MockRedisClient() as never, opts);
    const ctx = mockCtx({ headers: { authorization: 'Bearer token' } });
    const result = await shield.verify(ctx);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.reason).toBe('matched');
    }
  });

  it('produces deterministic fingerprints from same context', () => {
    const shield = new SessionShield(new MockRedisClient() as never, opts);
    const ctx = mockCtx({ headers: { authorization: 'Bearer token' } });
    const fp1 = shield.fingerprintOf(ctx);
    const fp2 = shield.fingerprintOf(ctx);
    expect(fp1).toBe(fp2);
  });

  it('produces different fingerprints for different contexts', () => {
    const shield = new SessionShield(new MockRedisClient() as never, opts);
    const ctx1 = mockCtx({ clientIp: '1.2.3.4', headers: { authorization: 'Bearer token' } });
    const ctx2 = mockCtx({ clientIp: '5.6.7.8', headers: { authorization: 'Bearer token' } });
    const fp1 = shield.fingerprintOf(ctx1);
    const fp2 = shield.fingerprintOf(ctx2);
    expect(fp1).not.toBe(fp2);
  });

  it('encryptFor returns null when no encryptFpClaim', async () => {
    const shield = new SessionShield(new MockRedisClient() as never, opts);
    const result = await shield.encryptFor(mockCtx({ headers: { authorization: 'Bearer token' } }));
    expect(result).toBeNull();
  });

  it('flag mode allows mismatches', async () => {
    const shield = new SessionShield(new MockRedisClient() as never, {
      ...opts,
      onMismatch: 'flag',
      extractClaims: (ctx) => {
        const auth = ctx.headers['authorization'] as string | undefined;
        if (!auth) return null;
        return {
          sub: 'user-1',
          jti: 'jti-abc',
          fp: '0000000000000000000000000000000000000000000000000000000000000000',
          exp: Date.now() / 1000 + 3600,
        };
      },
    });
    const ctx = mockCtx({ headers: { authorization: 'Bearer token' } });
    const result = await shield.verify(ctx);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.reason).toBe('fingerprint_mismatch');
    }
  });
});
