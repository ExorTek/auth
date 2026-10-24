/**
 * BLAKE2b against RFC 7693 Appendix A and node's own unkeyed blake2b512.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';

import { blake2b } from '../src/internal/blake2b.js';

test('RFC 7693 Appendix A: BLAKE2b-512("abc")', () => {
  const expected =
    'ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1' +
    '7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923';
  assert.equal(Buffer.from(blake2b(Buffer.from('abc'))).toString('hex'), expected);
});

test('unkeyed 64-byte digests match node blake2b512 across block boundaries', () => {
  for (const size of [0, 1, 127, 128, 129, 255, 256, 257, 1000, 4096]) {
    const msg = randomBytes(size);
    assert.equal(
      Buffer.from(blake2b(msg)).toString('hex'),
      createHash('blake2b512').update(msg).digest('hex'),
      `size ${size}`,
    );
  }
});

test('keyed BLAKE2b of an empty message uses the key block as the final block', () => {
  // RFC 7693 Appendix-style keyed vector (BLAKE2b-512, key = 00..3f, msg = '').
  const key = Uint8Array.from({ length: 64 }, (_, i) => i);
  const expected =
    '10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786' +
    'b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568';
  assert.equal(Buffer.from(blake2b(new Uint8Array(0), { key })).toString('hex'), expected);
});
