import { Ja4Bridge, DEFAULT_JA4_FAMILY_MAP } from '../src/modules/ja4-bridge';
import type { RequestContext } from '../src/types';

function mockCtx(overrides?: Partial<RequestContext>): RequestContext {
  return {
    method: 'GET',
    path: '/api/test',
    clientIp: '1.2.3.4',
    userAgent: 'Mozilla/5.0 Chrome/120',
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

describe('Ja4Bridge', () => {
  it('allows matching JA4+UA pairs', () => {
    const bridge = new Ja4Bridge();
    const ctx = mockCtx({
      userAgent: 'Mozilla/5.0 Chrome/120',
      jaFingerprint: 't13d1516h2_8daaf6152771_b0da82dd2788',
    });
    const result = bridge.verify(ctx);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.mismatch).toBe(false);
    }
  });

  it('blocks mismatched JA4+UA pairs', () => {
    const bridge = new Ja4Bridge();
    const ctx = mockCtx({
      userAgent: 'Mozilla/5.0 Chrome/120',
      jaFingerprint: 't13d1715h2_xxxx', // Firefox JA4 prefix
    });
    const result = bridge.verify(ctx);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.kind).toBe('tls_spoofing');
    }
  });

  it('classifies bot UAs as other', () => {
    const bridge = new Ja4Bridge();
    expect(bridge.classifyUserAgent('python-requests/2.28')).toBe('other');
    expect(bridge.classifyUserAgent('curl/7.88')).toBe('other');
    expect(bridge.classifyUserAgent('')).toBe('other');
  });

  it('classifies Chrome UAs correctly', () => {
    const bridge = new Ja4Bridge();
    expect(bridge.classifyUserAgent('Mozilla/5.0 Chrome/120')).toBe('chrome');
  });

  it('classifies Firefox UAs correctly', () => {
    const bridge = new Ja4Bridge();
    expect(bridge.classifyUserAgent('Mozilla/5.0 Firefox/120')).toBe('firefox');
  });

  it('classifies Edge before Chrome', () => {
    const bridge = new Ja4Bridge();
    expect(bridge.classifyUserAgent('Mozilla/5.0 Edg/120 Chrome/120')).toBe('edge');
  });

  it('excludes health routes by default', () => {
    const bridge = new Ja4Bridge();
    const ctx = mockCtx({ path: '/health' });
    const result = bridge.verify(ctx);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.exempt).toBe(true);
    }
  });

  it('allows unknown JA4 with other UA', () => {
    const bridge = new Ja4Bridge();
    const ctx = mockCtx({
      userAgent: 'python-requests/2.28',
      jaFingerprint: 'some_unknown_prefix_1234',
    });
    const result = bridge.verify(ctx);
    expect(result.ok).toBe(true);
  });

  it('flags when JA4 missing for desktop UA', () => {
    const bridge = new Ja4Bridge();
    const ctx = mockCtx({
      userAgent: 'Mozilla/5.0 Chrome/120',
      jaFingerprint: '',
    });
    const result = bridge.verify(ctx);
    expect(result.ok).toBe(false);
  });

  it('uses alternate headers for JA fingerprint', () => {
    const bridge = new Ja4Bridge({
      alternateJaHeaders: ['x-custom-ja4'],
    });
    const ctx = mockCtx({
      userAgent: 'Mozilla/5.0 Chrome/120',
      headers: { 'x-custom-ja4': 't13d1516h2_test' },
    });
    const result = bridge.verify(ctx);
    expect(result.ok).toBe(true);
  });

  it('DEFAULT_JA4_FAMILY_MAP has expected structure', () => {
    expect(DEFAULT_JA4_FAMILY_MAP).toBeDefined();
    expect(Object.keys(DEFAULT_JA4_FAMILY_MAP).length).toBeGreaterThan(0);
  });
});
