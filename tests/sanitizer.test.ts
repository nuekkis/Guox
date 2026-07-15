import { Sanitizer } from '../src/modules/sanitizer';
import type { RequestContext } from '../src/types';

function mockCtx(overrides?: Partial<RequestContext>): RequestContext {
  return {
    method: 'POST',
    path: '/api/data',
    clientIp: '1.2.3.4',
    userAgent: 'test-agent',
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

describe('Sanitizer', () => {
  it('passes clean objects through', () => {
    const s = new Sanitizer();
    const ctx = mockCtx({ parsedBody: { name: 'hello', age: 42 } });
    const result = s.sanitize(ctx);
    expect(result.ok).toBe(true);
  });

  it('removes __proto__ keys', () => {
    const s = new Sanitizer({ forbiddenAction: 'drop_key', forbiddenKeys: ['evil_key'] });
    const payload = { name: 'safe', evil_key: 'nasty' };
    const ctx = mockCtx({ parsedBody: payload });
    const result = s.sanitize(ctx);
    expect(result.ok).toBe(true);
    expect(result.forbiddenStripped).toBe(1);
  });

  it('removes constructor keys', () => {
    const s = new Sanitizer({ forbiddenAction: 'drop_key' });
    const payload = { constructor: { prototype: { admin: true } } };
    const ctx = mockCtx({ parsedBody: payload });
    const result = s.sanitize(ctx);
    expect(result.ok).toBe(true);
    expect(result.forbiddenStripped).toBeGreaterThan(0);
  });

  it('removes prototype keys', () => {
    const s = new Sanitizer({ forbiddenAction: 'drop_key' });
    const payload = { prototype: { polluted: true } };
    const ctx = mockCtx({ parsedBody: payload });
    const result = s.sanitize(ctx);
    expect(result.ok).toBe(true);
    expect(result.forbiddenStripped).toBeGreaterThan(0);
  });

  it('rejects deep payloads beyond maxDepth', () => {
    const s = new Sanitizer({ maxDepth: 2 });
    const deep = { a: { b: { c: { d: 'deep' } } } };
    const ctx = mockCtx({ parsedBody: deep });
    const result = s.sanitize(ctx);
    expect(result.ok).toBe(false);
    expect(result.rejectKind).toBe('payload_too_deep');
  });

  it('rejects oversized payloads', () => {
    const s = new Sanitizer({ maxBytes: 10 });
    const ctx = mockCtx({ rawBody: Buffer.from('this is way too long for 10 bytes') });
    const result = s.sanitize(ctx);
    expect(result.ok).toBe(false);
    expect(result.rejectKind).toBe('payload_oversize');
  });

  it('returns ok for null body', () => {
    const s = new Sanitizer();
    const ctx = mockCtx({ parsedBody: null });
    const result = s.sanitize(ctx);
    expect(result.ok).toBe(true);
  });

  it('returns ok for undefined body', () => {
    const s = new Sanitizer();
    const ctx = mockCtx({ parsedBody: undefined });
    const result = s.sanitize(ctx);
    expect(result.ok).toBe(true);
  });

  it('can drop_request on forbidden keys', () => {
    const s = new Sanitizer({ forbiddenAction: 'drop_request', forbiddenKeys: ['evil_key'] });
    const payload = { name: 'safe', evil_key: 'nasty' };
    const ctx = mockCtx({ parsedBody: payload });
    const result = s.sanitize(ctx);
    expect(result.ok).toBe(false);
    expect(result.rejectKind).toBe('prototype_pollution');
  });

  it('handles circular references', () => {
    const s = new Sanitizer({ onCircular: 'drop_request' });
    const a: Record<string, unknown> = { name: 'a' };
    const b: Record<string, unknown> = { name: 'b' };
    a.ref = b;
    b.ref = a;
    const ctx = mockCtx({ parsedBody: a });
    const result = s.sanitize(ctx);
    expect(result.ok).toBe(false);
  });

  it('excludes matched routes', () => {
    const s = new Sanitizer();
    s.setExcludes(['POST /health']);
    const ctx = mockCtx({ method: 'POST', path: '/health', parsedBody: { __proto__: { x: 1 } } });
    const result = s.sanitize(ctx);
    expect(result.ok).toBe(true);
    expect(result.forbiddenStripped).toBe(0);
  });

  it('buildRejectEvent returns correct event shape', () => {
    const s = new Sanitizer();
    const ctx = mockCtx();
    const result = { ok: false, rejectKind: 'prototype_pollution' as const, inspectedKeys: 5, forbiddenStripped: 1 };
    const evt = s.buildRejectEvent(ctx, result);
    expect(evt.kind).toBe('prototype_pollution');
    expect(evt.clientIp).toBe('1.2.3.4');
  });

  it('sanitizes query params as well', () => {
    const s = new Sanitizer({ forbiddenAction: 'drop_key' });
    const ctx = mockCtx({
      parsedQuery: { search: 'test', __proto__: 'polluted' },
    });
    const result = s.sanitize(ctx);
    expect(result.ok).toBe(true);
  });
});
