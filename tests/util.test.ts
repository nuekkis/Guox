import {
  compileGlob,
  header,
  sha256Hex,
  sha256Buf,
  freshRequestId,
  timingSafeStringEq,
  timingSafeBufEq,
  canonicalizeIp,
  ipToSubnet,
  resolveClientIp,
  LruMap,
  MemoryTokenBucket,
  nowSec,
  nowMs,
  ceilToAtLeast1,
} from '../src/util';

describe('compileGlob', () => {
  it('matches exact patterns', () => {
    const m = compileGlob('GET /health');
    expect(m('GET /health')).toBe(true);
    expect(m('POST /health')).toBe(false);
  });

  it('matches * wildcards', () => {
    const m = compileGlob('POST /users/*');
    expect(m('POST /users/42')).toBe(true);
    expect(m('POST /users/42/')).toBe(false);
  });

  it('matches ** wildcards', () => {
    const m = compileGlob('POST /users/**');
    expect(m('POST /users/42')).toBe(true);
    expect(m('POST /users/42/')).toBe(true);
    expect(m('POST /users/42/orders')).toBe(true);
  });

  it('matches ? single char', () => {
    const m = compileGlob('GET /?');
    expect(m('GET /a')).toBe(true);
    expect(m('GET /ab')).toBe(false);
  });

  it('returns false for empty pattern', () => {
    const m = compileGlob('');
    expect(m('anything')).toBe(false);
  });
});

describe('header', () => {
  it('reads header case-insensitively', () => {
    const h = { 'content-type': 'application/json' };
    expect(header(h, 'Content-Type')).toBe('application/json');
  });

  it('returns empty string for missing header', () => {
    expect(header({}, 'x-missing')).toBe('');
  });

  it('joins array headers', () => {
    const h = { 'set-cookie': ['a=1', 'b=2'] };
    expect(header(h, 'set-cookie')).toBe('a=1,b=2');
  });
});

describe('sha256Hex', () => {
  it('returns 64 char hex string', () => {
    const result = sha256Hex('hello');
    expect(result).toHaveLength(64);
    expect(/^[0-9a-f]+$/.test(result)).toBe(true);
  });

  it('is deterministic', () => {
    expect(sha256Hex('test')).toBe(sha256Hex('test'));
  });
});

describe('sha256Buf', () => {
  it('hashes a buffer', () => {
    const buf = Buffer.from('hello', 'utf8');
    const result = sha256Buf(buf);
    expect(result).toHaveLength(64);
  });
});

describe('freshRequestId', () => {
  it('generates a url-safe string', () => {
    const id = freshRequestId();
    expect(typeof id).toBe('string');
    expect(id.length).toBeGreaterThan(0);
    expect(/^[A-Za-z0-9_-]+$/.test(id)).toBe(true);
  });

  it('generates unique IDs', () => {
    const ids = new Set(Array.from({ length: 100 }, () => freshRequestId()));
    expect(ids.size).toBe(100);
  });
});

describe('timingSafeStringEq', () => {
  it('returns true for equal strings', () => {
    expect(timingSafeStringEq('abc', 'abc')).toBe(true);
  });

  it('returns false for different strings', () => {
    expect(timingSafeStringEq('abc', 'xyz')).toBe(false);
  });

  it('short-circuits on length mismatch', () => {
    expect(timingSafeStringEq('a', 'ab')).toBe(false);
  });
});

describe('timingSafeBufEq', () => {
  it('returns true for equal buffers', () => {
    expect(timingSafeBufEq(Buffer.from('abc'), Buffer.from('abc'))).toBe(true);
  });

  it('returns false for different buffers', () => {
    expect(timingSafeBufEq(Buffer.from('abc'), Buffer.from('xyz'))).toBe(false);
  });

  it('short-circuits on length mismatch', () => {
    expect(timingSafeBufEq(Buffer.from('a'), Buffer.from('ab'))).toBe(false);
  });
});

describe('canonicalizeIp', () => {
  it('removes IPv6 zone id', () => {
    expect(canonicalizeIp('fe80::1%eth0')).toBe('fe80::1');
  });

  it('strips brackets and normalizes loopback', () => {
    expect(canonicalizeIp('[::1]')).toBe('127.0.0.1');
  });

  it('unmaps IPv4-mapped IPv6', () => {
    expect(canonicalizeIp('::ffff:192.168.1.1')).toBe('192.168.1.1');
  });

  it('normalizes ::1 to 127.0.0.1', () => {
    expect(canonicalizeIp('::1')).toBe('127.0.0.1');
  });

  it('returns 0.0.0.0 for empty string', () => {
    expect(canonicalizeIp('')).toBe('0.0.0.0');
  });
});

describe('ipToSubnet', () => {
  it('returns /24 for IPv4', () => {
    expect(ipToSubnet('192.168.1.42')).toBe('192.168.1');
  });

  it('returns /48 for IPv6', () => {
    const result = ipToSubnet('2001:db8::1');
    expect(result).toBe('2001:db8:');
  });
});

describe('resolveClientIp', () => {
  it('uses rawIp when no proxy headers', () => {
    const result = resolveClientIp({}, '10.0.0.1', 0);
    expect(result).toBe('10.0.0.1');
  });

  it('respects trustProxyHops', () => {
    const headers = { 'x-forwarded-for': '1.2.3.4, 5.6.7.8' };
    const result = resolveClientIp(headers, '10.0.0.1', 1);
    expect(result).toBe('1.2.3.4');
  });

  it('falls back when no IP available', () => {
    expect(resolveClientIp({}, undefined, 0)).toBe('0.0.0.0');
  });
});

describe('LruMap', () => {
  it('stores and retrieves values', () => {
    const m = new LruMap<string, number>(10);
    m.set('a', 1);
    expect(m.get('a')).toBe(1);
  });

  it('evicts oldest when over capacity', () => {
    const m = new LruMap<string, number>(2);
    m.set('a', 1);
    m.set('b', 2);
    m.set('c', 3);
    expect(m.has('a')).toBe(false);
    expect(m.get('b')).toBe(2);
    expect(m.get('c')).toBe(3);
  });

  it('re-insert marks MRU', () => {
    const m = new LruMap<string, number>(2);
    m.set('a', 1);
    m.set('b', 2);
    m.get('a');
    m.set('c', 3);
    expect(m.has('a')).toBe(true);
    expect(m.has('b')).toBe(false);
  });

  it('delete removes entry', () => {
    const m = new LruMap<string, number>(10);
    m.set('a', 1);
    expect(m.delete('a')).toBe(true);
    expect(m.get('a')).toBeUndefined();
  });

  it('clear empties map', () => {
    const m = new LruMap<string, number>(10);
    m.set('a', 1);
    m.set('b', 2);
    m.clear();
    expect(m.size).toBe(0);
  });

  it('throws on invalid max', () => {
    expect(() => new LruMap(0)).toThrow('LruMap max must be >= 1');
  });
});

describe('MemoryTokenBucket', () => {
  beforeEach(() => {
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it('allows charges within capacity', () => {
    const bucket = new MemoryTokenBucket(10, 10, 1);
    const remaining = bucket.charge(3);
    expect(remaining).toBeGreaterThanOrEqual(0);
  });

  it('rejects charges over capacity', () => {
    const bucket = new MemoryTokenBucket(10, 10, 1);
    bucket.charge(10);
    const remaining = bucket.charge(1);
    expect(remaining).toBe(-1);
  });

  it('refills over time', () => {
    const bucket = new MemoryTokenBucket(10, 10, 1);
    bucket.charge(10);
    jest.advanceTimersByTime(2000);
    const remaining = bucket.charge(1);
    expect(remaining).toBeGreaterThanOrEqual(0);
  });
});

describe('nowSec / nowMs / ceilToAtLeast1', () => {
  it('nowSec returns integer seconds', () => {
    const val = nowSec();
    expect(Number.isInteger(val)).toBe(true);
    expect(val).toBeGreaterThan(1_600_000_000);
  });

  it('nowMs returns milliseconds', () => {
    const val = nowMs();
    expect(val).toBeGreaterThan(1_600_000_000_000);
  });

  it('ceilToAtLeast1 floors at 1', () => {
    expect(ceilToAtLeast1(0)).toBe(1);
    expect(ceilToAtLeast1(-5)).toBe(1);
    expect(ceilToAtLeast1(2.3)).toBe(3);
    expect(ceilToAtLeast1(1)).toBe(1);
  });
});
