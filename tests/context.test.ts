import { buildContext, resolveIdentityOn } from '../src/context';
import type { AdapterRequest } from '../src/types';

function mockReq(overrides?: Partial<AdapterRequest>): AdapterRequest {
  return {
    method: 'GET',
    path: '/api/test',
    url: '/api/test?q=1',
    headers: { 'user-agent': 'TestAgent/1.0', 'x-api-key': 'secret-123' },
    rawBody: Buffer.alloc(0),
    ...overrides,
  };
}

describe('buildContext', () => {
  it('builds a minimal context', () => {
    const ctx = buildContext(mockReq(), { trustProxyHops: 1 }, ['ip']);
    expect(ctx.method).toBe('GET');
    expect(ctx.path).toBe('/api/test');
    expect(ctx.requestId).toBeDefined();
    expect(ctx.receivedAt).toBeGreaterThan(0);
  });

  it('canonicalizes user-agent', () => {
    const ctx = buildContext(
      mockReq({ headers: { 'user-agent': '  MyAgent/1.0  ' } }),
      { trustProxyHops: 0 },
      ['ip'],
    );
    expect(ctx.userAgent).toBe('myagent/1.0');
  });

  it('resolves client IP from x-forwarded-for', () => {
    const ctx = buildContext(
      mockReq({ headers: { 'x-forwarded-for': '10.0.0.1' }, ip: '192.168.1.1' }),
      { trustProxyHops: 1 },
      ['ip'],
    );
    expect(ctx.clientIp).toBe('10.0.0.1');
  });

  it('falls back to socket ip when no x-forwarded-for', () => {
    const ctx = buildContext(mockReq({ ip: '10.0.0.1' }), { trustProxyHops: 0 }, ['ip']);
    expect(ctx.clientIp).toBe('10.0.0.1');
  });

  it('resolves identity eagerly when custom resolveIdentity provided', () => {
    const ctx = buildContext(
      mockReq(),
      { trustProxyHops: 1 },
      ['custom'],
      () => ({ identity: 'custom:user123' as never, strategy: 'custom' as const }),
    );
    expect(ctx.identity).not.toBeNull();
  });

  it('handles resolveIdentity returning null gracefully', () => {
    const ctx = buildContext(
      mockReq(),
      { trustProxyHops: 1 },
      ['ip'],
      () => null,
    );
    expect(ctx.identity).toBeNull();
  });
});

describe('resolveIdentityOn', () => {
  it('returns memoized identity if already set', () => {
    const ctx = buildContext(mockReq(), { trustProxyHops: 1 }, ['ip']);
    ctx.identity = { identity: 'memoized' as never, strategy: 'ip' };
    const result = resolveIdentityOn(ctx, ['api_key', 'jwt_sub', 'ip']);
    expect(result!.identity).toBe('memoized' as never);
  });

  it('resolves from api_key strategy', () => {
    const ctx = buildContext(
      mockReq({ headers: { 'x-api-key': 'key-123' } }),
      { trustProxyHops: 1 },
      ['api_key', 'ip'],
    );
    ctx.identity = null;
    const result = resolveIdentityOn(ctx, ['api_key', 'jwt_sub', 'ip']);
    expect(result).not.toBeNull();
    expect(result!.strategy).toBe('api_key');
  });

  it('resolves from ip fallback', () => {
    const ctx = buildContext(mockReq(), { trustProxyHops: 0 }, ['ip']);
    ctx.identity = null;
    const result = resolveIdentityOn(ctx, ['ip']);
    expect(result).not.toBeNull();
    expect(result!.strategy).toBe('ip');
  });

  it('uses custom strategy', () => {
    const ctx = buildContext(mockReq(), { trustProxyHops: 1 }, ['custom']);
    ctx.identity = null;
    const result = resolveIdentityOn(ctx, ['custom'], () => ({
      identity: 'custom-val' as never,
      strategy: 'custom' as const,
    }));
    expect(result).not.toBeNull();
    expect(result!.strategy).toBe('custom');
  });
});
