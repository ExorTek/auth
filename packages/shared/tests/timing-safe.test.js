import { test } from 'node:test';
import assert from 'node:assert/strict';

import { timingSafeEqual } from '../src/crypto/timing-safe.js';

test('equal buffers → true', () => {
  const a = Buffer.from('secret');
  const b = Buffer.from('secret');
  assert.equal(timingSafeEqual(a, b), true);
});

test('unequal-content buffers → false', () => {
  assert.equal(timingSafeEqual(Buffer.from('secret'), Buffer.from('secreT')), false);
});

test('unequal-length buffers → false, NEVER throws', () => {
  assert.equal(timingSafeEqual(Buffer.from('a'), Buffer.from('aaa')), false);
  assert.equal(timingSafeEqual(Buffer.from(''), Buffer.from('a')), false);
});

test('accepts Uint8Array input', () => {
  const a = new Uint8Array([1, 2, 3]);
  const b = new Uint8Array([1, 2, 3]);
  assert.equal(timingSafeEqual(a, b), true);
});
