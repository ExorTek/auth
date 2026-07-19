import { describe, test } from 'node:test';
import assert from 'node:assert/strict';

import { randomBuffer } from '../src/random.js';

describe('randomBuffer', () => {
  test('returns a Buffer of the requested size', () => {
    const buf = randomBuffer(16);
    assert.ok(Buffer.isBuffer(buf));
    assert.equal(buf.length, 16);
  });

  test('accepts size === 0', () => {
    assert.equal(randomBuffer(0).length, 0);
  });

  test('rejects negative sizes with a plain-Error path (not Node RangeError)', () => {
    assert.throws(() => randomBuffer(-1), /randomBuffer\.size must be a non-negative safe integer/);
  });

  test('rejects non-integer sizes', () => {
    assert.throws(() => randomBuffer(1.5), /randomBuffer\.size must be a non-negative safe integer/);
  });

  test('rejects NaN', () => {
    assert.throws(() => randomBuffer(NaN), /randomBuffer\.size must be a non-negative safe integer/);
  });

  test('rejects non-number', () => {
    assert.throws(() => randomBuffer('16'), /randomBuffer\.size must be a non-negative safe integer/);
    assert.throws(() => randomBuffer(null), /randomBuffer\.size must be a non-negative safe integer/);
    assert.throws(() => randomBuffer(undefined), /randomBuffer\.size must be a non-negative safe integer/);
  });
});
