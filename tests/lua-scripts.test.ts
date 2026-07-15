import {
  decodeRateLimitResult,
  decodeNonceResult,
  decodeIpReputationResult,
} from '../src/lua-scripts';

describe('decodeRateLimitResult', () => {
  it('decodes allowed response', () => {
    const result = decodeRateLimitResult(['1', '85', '0', '15', '100']);
    expect(result.allowed).toBe(true);
    expect(result.remaining).toBe(85);
    expect(result.retryAfter).toBe(0);
    expect(result.charged).toBe(15);
    expect(result.limit).toBe(100);
  });

  it('decodes denied response', () => {
    const result = decodeRateLimitResult(['0', '0', '12', '0', '100']);
    expect(result.allowed).toBe(false);
    expect(result.remaining).toBe(0);
    expect(result.retryAfter).toBe(12);
    expect(result.charged).toBe(0);
  });

  it('handles empty array', () => {
    const result = decodeRateLimitResult([]);
    expect(result.allowed).toBe(false);
    expect(result.remaining).toBe(0);
  });

  it('handles non-array input', () => {
    const result = decodeRateLimitResult(null);
    expect(result.allowed).toBe(false);
  });
});

describe('decodeNonceResult', () => {
  it('returns true when nonce is fresh', () => {
    expect(decodeNonceResult(['1'])).toBe(true);
  });

  it('returns false when nonce exists', () => {
    expect(decodeNonceResult(['0'])).toBe(false);
  });

  it('handles non-array input', () => {
    expect(decodeNonceResult(null)).toBe(false);
  });
});

describe('decodeIpReputationResult', () => {
  it('decodes blocked result', () => {
    const r = decodeIpReputationResult(['1', '3']);
    expect(r.blockedNow).toBe(true);
    expect(r.violations).toBe(3);
  });

  it('decodes not blocked result', () => {
    const r = decodeIpReputationResult(['0', '1']);
    expect(r.blockedNow).toBe(false);
    expect(r.violations).toBe(1);
  });

  it('handles non-array input', () => {
    const r = decodeIpReputationResult(null);
    expect(r.blockedNow).toBe(false);
    expect(r.violations).toBe(0);
  });
});
