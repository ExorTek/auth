import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { fingerprint, hash } from '../../src/index.js';
import { CryptoError, ErrorCode } from '../../src/errors.js';

describe('fingerprint', () => {
  it('returns a sha256 hex string by default', () => {
    const fp = fingerprint({ a: 1 });
    assert.equal(typeof fp, 'string');
    assert.match(fp, /^[0-9a-f]{64}$/);
  });

  it('is stable across key order', () => {
    assert.equal(fingerprint({ a: 1, b: 2 }), fingerprint({ b: 2, a: 1 }));
    assert.equal(fingerprint({ z: [1, 2], a: 'x' }), fingerprint({ a: 'x', z: [1, 2] }));
  });

  it('respects array order (arrays are ordered)', () => {
    assert.notEqual(fingerprint([1, 2, 3]), fingerprint([3, 2, 1]));
  });

  it('discriminates trivially different inputs', () => {
    assert.notEqual(fingerprint({ a: 1 }), fingerprint({ a: 2 }));
    assert.notEqual(fingerprint({ a: 1 }), fingerprint({ b: 1 }));
    assert.notEqual(fingerprint(null), fingerprint('null'));
    assert.notEqual(fingerprint(1), fingerprint('1'));
    assert.notEqual(fingerprint(true), fingerprint('true'));
  });

  it('canonical form matches expected sha256', () => {
    // Canonical: {"a":1,"b":[2,3]}
    const expected = hash('{"a":1,"b":[2,3]}');
    assert.equal(fingerprint({ b: [2, 3], a: 1 }), expected);
  });

  it('accepts primitives', () => {
    assert.equal(fingerprint('hello'), hash('"hello"'));
    assert.equal(fingerprint(42), hash('42'));
    assert.equal(fingerprint(true), hash('true'));
    assert.equal(fingerprint(null), hash('null'));
  });

  it('handles nested structures', () => {
    const a = { user: { id: 1, roles: ['admin', 'user'] }, meta: null };
    const b = { meta: null, user: { roles: ['admin', 'user'], id: 1 } };
    assert.equal(fingerprint(a), fingerprint(b));
  });

  it('unwraps .toJSON() (e.g. Date)', () => {
    const d = new Date('2026-07-06T00:00:00.000Z');
    assert.equal(fingerprint({ at: d }), fingerprint({ at: d.toISOString() }));
  });

  it('honours options.algo and options.encoding', () => {
    const bufFp = fingerprint({ a: 1 }, { algo: 'sha512', encoding: 'buffer' });
    assert.ok(Buffer.isBuffer(bufFp));
    assert.equal(bufFp.length, 64);
    const b64 = fingerprint({ a: 1 }, { encoding: 'base64url' });
    assert.match(b64, /^[A-Za-z0-9_-]+$/);
  });

  it('rejects undefined, bigint, symbol, function', () => {
    for (const bad of [undefined, 1n, Symbol('x'), () => 0]) {
      assert.throws(
        () => fingerprint(bad),
        err => err.code === ErrorCode.INVALID_ARGUMENT,
      );
    }
  });

  it('rejects NaN and Infinity', () => {
    for (const bad of [NaN, Infinity, -Infinity]) {
      assert.throws(
        () => fingerprint(bad),
        err => err.code === ErrorCode.INVALID_ARGUMENT,
      );
    }
  });

  it('rejects Buffer / Uint8Array (must be encoded first)', () => {
    for (const bad of [Buffer.from('hi'), new Uint8Array([1, 2, 3])]) {
      assert.throws(
        () => fingerprint({ data: bad }),
        err => err.code === ErrorCode.INVALID_ARGUMENT,
      );
    }
  });

  it('rejects cyclic references', () => {
    const a = { name: 'a' };
    a.self = a;
    assert.throws(
      () => fingerprint(a),
      err => err.code === ErrorCode.INVALID_ARGUMENT,
    );
  });

  it('rejects unsupported algo', () => {
    assert.throws(
      () => fingerprint({ a: 1 }, { algo: 'blake2b' }),
      err => err instanceof CryptoError && err.code === ErrorCode.UNSUPPORTED_ALGORITHM,
    );
  });
});
