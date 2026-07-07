import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { seal, unseal } from '../../src/index.js';
import { CryptoError, ErrorCode } from '../../src/errors.js';

const SECRET = 'shhh-do-not-share-i-am-32-bytes+';

describe('seal / unseal', () => {
  it('round-trips a JSON object', () => {
    const token = seal({ userId: 42, purpose: 'pw-reset' }, SECRET, { ttl: '1h' });
    const { payload, expiresAt } = unseal(token, SECRET);
    assert.deepEqual(payload, { userId: 42, purpose: 'pw-reset' });
    assert.ok(expiresAt > Date.now());
  });

  it('round-trips a string payload', () => {
    const token = seal('hello', SECRET, { ttl: 60 });
    assert.equal(unseal(token, SECRET).payload, 'hello');
  });

  it('round-trips null / boolean / number', () => {
    for (const value of [null, true, false, 0, 42]) {
      const token = seal(value, SECRET, { ttl: 60 });
      assert.equal(unseal(token, SECRET).payload, value);
    }
  });

  it('output is base64url', () => {
    const token = seal({ a: 1 }, SECRET, { ttl: 60 });
    assert.match(token, /^[A-Za-z0-9_-]+$/);
  });

  it('is non-deterministic (random IV)', () => {
    const t1 = seal({ a: 1 }, SECRET, { ttl: 60 });
    const t2 = seal({ a: 1 }, SECRET, { ttl: 60 });
    assert.notEqual(t1, t2);
  });

  it('accepts ttl as number of seconds', () => {
    const now = 1_000_000_000_000;
    const token = seal({ a: 1 }, SECRET, { ttl: 900, now });
    assert.equal(unseal(token, SECRET, { now }).expiresAt, now + 900_000);
  });

  it('accepts duration strings ms/s/m/h/d/w', () => {
    const now = 1_000_000_000_000;
    const cases = [
      ['500ms', 500],
      ['30s', 30_000],
      ['15m', 900_000],
      ['1h', 3_600_000],
      ['7d', 7 * 86_400_000],
      ['2w', 2 * 604_800_000],
    ];
    for (const [ttl, ms] of cases) {
      const token = seal({}, SECRET, { ttl, now });
      assert.equal(unseal(token, SECRET, { now }).expiresAt - now, ms);
    }
  });

  it('accepts Buffer secret', () => {
    const secret = Buffer.alloc(32, 0xa5);
    const token = seal({ x: 1 }, secret, { ttl: 60 });
    assert.deepEqual(unseal(token, secret).payload, { x: 1 });
  });
});

describe('unseal — failure modes', () => {
  it('TOKEN_TAMPERED for wrong secret', () => {
    const token = seal({ a: 1 }, 'right', { ttl: 60 });
    assert.throws(
      () => unseal(token, 'wrong'),
      err => err instanceof CryptoError && err.code === ErrorCode.TOKEN_TAMPERED,
    );
  });

  it('TOKEN_TAMPERED for a flipped byte', () => {
    const token = seal({ a: 1 }, SECRET, { ttl: 60 });
    const bytes = Buffer.from(token, 'base64url');
    bytes[bytes.length - 3] ^= 0xff;
    const tampered = bytes.toString('base64url');
    assert.throws(
      () => unseal(tampered, SECRET),
      err => err instanceof CryptoError && err.code === ErrorCode.TOKEN_TAMPERED,
    );
  });

  it('TOKEN_MALFORMED for a truncated token', () => {
    const token = seal({ a: 1 }, SECRET, { ttl: 60 });
    assert.throws(
      () => unseal(token.slice(0, 10), SECRET),
      err => err instanceof CryptoError && err.code === ErrorCode.TOKEN_MALFORMED,
    );
  });

  it('TOKEN_MALFORMED for a wrong version byte', () => {
    const token = seal({ a: 1 }, SECRET, { ttl: 60 });
    const bytes = Buffer.from(token, 'base64url');
    bytes[0] = 0xff;
    assert.throws(
      () => unseal(bytes.toString('base64url'), SECRET),
      err => err instanceof CryptoError && err.code === ErrorCode.TOKEN_MALFORMED,
    );
  });

  it('TOKEN_MALFORMED for a non-string token', () => {
    for (const bad of [null, undefined, 42, {}, Buffer.from('x')]) {
      assert.throws(
        () => unseal(bad, SECRET),
        err => err instanceof CryptoError && err.code === ErrorCode.TOKEN_MALFORMED,
      );
    }
  });

  it('TOKEN_EXPIRED after the ttl elapses', () => {
    const t0 = 1_000_000_000_000;
    const token = seal({ a: 1 }, SECRET, { ttl: 60, now: t0 });
    assert.throws(
      () => unseal(token, SECRET, { now: t0 + 60_001 }),
      err => err instanceof CryptoError && err.code === ErrorCode.TOKEN_EXPIRED,
    );
  });

  it('clockSkew grace window keeps a slightly-expired token valid', () => {
    const t0 = 1_000_000_000_000;
    const token = seal({ a: 1 }, SECRET, { ttl: 60, now: t0 });
    // 5s past expiry, 10s skew allowed → still valid.
    assert.deepEqual(unseal(token, SECRET, { now: t0 + 65_000, clockSkew: 10 }).payload, { a: 1 });
  });

  it('expiry is authenticated — cannot be extended by editing bytes', () => {
    const t0 = 1_000_000_000_000;
    const token = seal({ a: 1 }, SECRET, { ttl: 60, now: t0 });
    const bytes = Buffer.from(token, 'base64url');
    // Overwrite the expiresAt field (bytes 13..20) with a value 1 hour later.
    bytes.writeBigUInt64BE(BigInt(t0 + 3_600_000), 13);
    assert.throws(
      () => unseal(bytes.toString('base64url'), SECRET, { now: t0 + 120_000 }),
      // Tampering the expiry breaks GCM auth, not just expiry check.
      err => err instanceof CryptoError && err.code === ErrorCode.TOKEN_TAMPERED,
    );
  });
});

describe('seal — argument validation', () => {
  it('rejects missing options.ttl', () => {
    assert.throws(
      () => seal({}, SECRET),
      err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
    );
    assert.throws(
      () => seal({}, SECRET, {}),
      err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
    );
  });

  it('rejects malformed duration strings', () => {
    for (const bad of ['', '15x', '-1h', 'abc', '1 h', '1.5h']) {
      assert.throws(
        () => seal({}, SECRET, { ttl: bad }),
        err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
      );
    }
  });

  it('rejects non-positive numeric ttl', () => {
    for (const bad of [0, -1, 1.5, NaN, Infinity]) {
      assert.throws(
        () => seal({}, SECRET, { ttl: bad }),
        err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
      );
    }
  });

  it('rejects undefined payload (JSON.stringify → undefined)', () => {
    assert.throws(
      () => seal(undefined, SECRET, { ttl: 60 }),
      err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
    );
  });

  it('rejects cyclic payload', () => {
    const a = { name: 'a' };
    a.self = a;
    assert.throws(
      () => seal(a, SECRET, { ttl: 60 }),
      err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
    );
  });
});
