import { test } from 'node:test';
import assert from 'node:assert/strict';

import { encode, decode } from '../src/base32.js';

test('encode: RFC 4648 §6 vectors (unpadded)', () => {
  assert.equal(encode(Buffer.from('')), '');
  assert.equal(encode(Buffer.from('f')), 'MY');
  assert.equal(encode(Buffer.from('fo')), 'MZXQ');
  assert.equal(encode(Buffer.from('foo')), 'MZXW6');
  assert.equal(encode(Buffer.from('foob')), 'MZXW6YQ');
  assert.equal(encode(Buffer.from('fooba')), 'MZXW6YTB');
  assert.equal(encode(Buffer.from('foobar')), 'MZXW6YTBOI');
});

test('encode: padding option aligns to 8 chars', () => {
  assert.equal(encode(Buffer.from('f'), { padding: true }), 'MY======');
  assert.equal(encode(Buffer.from('fooba'), { padding: true }), 'MZXW6YTB');
});

test('encode: rejects non-buffer input', () => {
  assert.throws(() => encode('nope'), TypeError);
  assert.throws(() => encode(null), TypeError);
});

test('decode: roundtrip, case-insensitive, padding-tolerant', () => {
  const bytes = Buffer.from([0, 1, 2, 250, 251, 252, 253, 254, 255]);
  assert.deepEqual(decode(encode(bytes)), bytes);
  assert.deepEqual(decode('mzxw6ytboi'), Buffer.from('foobar'));
  assert.deepEqual(decode('MZXW6YTB'), Buffer.from('fooba'));
  assert.deepEqual(decode('MY======'), Buffer.from('f'));
  assert.deepEqual(decode(''), Buffer.alloc(0));
});

test('decode: long input stays byte-exact (32-bit masking)', () => {
  const bytes = Buffer.alloc(1024);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = i % 256;
  }
  assert.deepEqual(decode(encode(bytes)), bytes);
});

test('decode: rejects characters outside the alphabet', () => {
  assert.throws(() => decode('MZXW6YT!'), /invalid base32 character/);
  assert.throws(() => decode('MZXW1'), /invalid base32 character/);
  assert.throws(() => decode(123), TypeError);
});
