import { ok, err, Identity, NonceHash, Ja4Fingerprint, FingerprintHash } from '../src/types';

describe('ok', () => {
  it('creates a success Result', () => {
    const r = ok(42);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.value).toBe(42);
    }
  });
});

describe('err', () => {
  it('creates an error Result', () => {
    const r = err({ kind: 'rate_limited', message: 'too fast', statusCode: 429 });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.error.kind).toBe('rate_limited');
      expect(r.error.statusCode).toBe(429);
    }
  });
});

describe('Identity', () => {
  it('brands a string', () => {
    const id = Identity('user:abc');
    expect(id).toBe('user:abc');
  });
});

describe('NonceHash', () => {
  it('brands a string', () => {
    const h = NonceHash('abc123');
    expect(h).toBe('abc123');
  });
});

describe('Ja4Fingerprint', () => {
  it('brands a string', () => {
    const fp = Ja4Fingerprint('t13d1516h2_8daaf6152771');
    expect(fp).toBe('t13d1516h2_8daaf6152771');
  });
});

describe('FingerprintHash', () => {
  it('brands a string', () => {
    const fp = FingerprintHash('a'.repeat(64));
    expect(fp).toBe('a'.repeat(64));
  });
});
