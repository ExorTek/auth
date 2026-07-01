import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { pin } from '../../src/index.js';
import { CryptoError, ErrorCode } from '../../src/errors.js';

const WEAK_4 = new Set([
  // all identical
  ...'0123456789'.split('').map((d) => d.repeat(4)),
  // ascending (wraps 9→0)
  '0123', '1234', '2345', '3456', '4567', '5678', '6789', '7890', '8901', '9012',
  // descending
  '3210', '4321', '5432', '6543', '7654', '8765', '9876', '0987', '1098', '2109',
]);

describe('pin', () => {
  it('returns a numeric string of the requested length', () => {
    for (const len of [3, 4, 6, 8]) {
      const p = pin(len);
      assert.equal(p.length, len);
      assert.match(p, /^[0-9]+$/);
    }
  });

  it('never produces a weak 4-digit PIN by default', () => {
    for (let i = 0; i < 5000; i++) {
      const p = pin(4);
      assert.ok(!WEAK_4.has(p), `expected non-weak PIN, got ${p}`);
    }
  });

  it('allows weak PINs when avoidWeak: false', () => {
    // With filter off we should occasionally see weak values in enough draws.
    let sawWeak = false;
    for (let i = 0; i < 20_000; i++) {
      if (WEAK_4.has(pin(4, { avoidWeak: false }))) {
        sawWeak = true;
        break;
      }
    }
    assert.ok(sawWeak, 'expected at least one weak PIN when filter is disabled');
  });

  it('preserves leading zeros', () => {
    // Sample many; some should start with 0.
    let sawLeadingZero = false;
    for (let i = 0; i < 2000; i++) {
      if (pin(4).startsWith('0')) {
        sawLeadingZero = true;
        break;
      }
    }
    assert.ok(sawLeadingZero);
  });

  it('rejects non-positive length', () => {
    assert.throws(() => pin(0), (err) => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT);
    assert.throws(() => pin(-1), (err) => err instanceof CryptoError);
    assert.throws(() => pin(1.5), (err) => err instanceof CryptoError);
    assert.throws(() => pin(NaN), (err) => err instanceof CryptoError);
  });

  it('rejects non-object options', () => {
    assert.throws(() => pin(4, 'true'), (err) => err instanceof CryptoError);
    assert.throws(() => pin(4, null), (err) => err instanceof CryptoError);
    assert.throws(() => pin(4, []), (err) => err instanceof CryptoError);
  });

  it('accepts short lengths (1-2) without applying the weak filter', () => {
    // Length < 3 has no meaningful "pattern"; should just return a digit.
    for (let i = 0; i < 20; i++) {
      const p1 = pin(1);
      const p2 = pin(2);
      assert.equal(p1.length, 1);
      assert.equal(p2.length, 2);
      assert.match(p1, /^[0-9]$/);
      assert.match(p2, /^[0-9]{2}$/);
    }
  });
});
