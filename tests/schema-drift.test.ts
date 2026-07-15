import { SchemaDrift } from '../src/modules/schema-drift';
import type { RequestContext } from '../src/types';

function mockCtx(overrides?: Partial<RequestContext>): RequestContext {
  return {
    method: 'POST',
    path: '/api/data',
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
    parsedBody: { email: 'test@example.com' },
    parsedQuery: undefined,
    parsedParams: undefined,
    ...overrides,
  };
}

describe('SchemaDrift', () => {
  it('skips when no resolver configured', () => {
    const sd = new SchemaDrift();
    const result = sd.check(mockCtx());
    expect(result.valid).toBe(true);
    expect(result.skipped).toBe(true);
  });

  it('validates matching payload', () => {
    const sd = new SchemaDrift({
      resolve: () => (body: unknown) => {
        const b = body as { email?: string };
        return { valid: typeof b?.email === 'string' };
      },
    });
    const result = sd.check(mockCtx({ parsedBody: { email: 'test@example.com' } }));
    expect(result.valid).toBe(true);
    expect(result.skipped).toBe(false);
  });

  it('detects schema drift', () => {
    const sd = new SchemaDrift({
      resolve: () => (body: unknown) => {
        const b = body as { email?: string };
        if (typeof b?.email !== 'string') {
          return { valid: false, errors: ['email must be a string'] };
        }
        return { valid: true };
      },
    });
    const result = sd.check(mockCtx({ parsedBody: { email: 42 } }));
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('email must be a string');
  });

  it('buildEvent returns proper shape', () => {
    const sd = new SchemaDrift({ onDrift: 'block' });
    const ctx = mockCtx();
    const evt = sd.buildEvent(ctx, { valid: false, errors: ['bad'], skipped: false });
    expect(evt.kind).toBe('schema_drift');
    expect(evt.severity).toBe('warn');
    expect(evt.context).toEqual({ errors: ['bad'] });
  });

  it('shouldBlock returns true when onDrift is block', () => {
    const sd = new SchemaDrift({ onDrift: 'block' });
    expect(sd.shouldBlock()).toBe(true);
  });

  it('shouldBlock returns false when onDrift is flag', () => {
    const sd = new SchemaDrift({ onDrift: 'flag' });
    expect(sd.shouldBlock()).toBe(false);
  });

  it('handles resolver returning null per-route', () => {
    const sd = new SchemaDrift({
      resolve: () => null,
    });
    const result = sd.check(mockCtx());
    expect(result.valid).toBe(true);
    expect(result.skipped).toBe(true);
  });

  it('handles validator that throws', () => {
    const sd = new SchemaDrift({
      resolve: () => () => { throw new Error('validator error'); },
    });
    const result = sd.check(mockCtx());
    expect(result.valid).toBe(false);
    expect(result.errors?.length).toBeGreaterThan(0);
  });
});
