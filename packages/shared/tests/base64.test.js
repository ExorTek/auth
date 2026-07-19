import { describe, test } from 'node:test';
import assert from 'node:assert/strict';

import { encode, decode } from '../src/base64.js';

describe('base64', () => {
  test('encode default strips trailing =', () => {
    assert.equal(encode(Buffer.from('any carnal pleasure.')), 'YW55IGNhcm5hbCBwbGVhc3VyZS4');
    assert.equal(encode(Buffer.from('a')), 'YQ');
    assert.equal(encode(Buffer.from('ab')), 'YWI');
    assert.equal(encode(Buffer.from('abc')), 'YWJj');
  });

  test('encode { pad: true } keeps the padding', () => {
    assert.equal(encode(Buffer.from('a'), { pad: true }), 'YQ==');
    assert.equal(encode(Buffer.from('ab'), { pad: true }), 'YWI=');
    assert.equal(encode(Buffer.from('abc'), { pad: true }), 'YWJj');
    assert.equal(encode(Buffer.alloc(0), { pad: true }), '');
  });

  test('encode { pad: false } is the default', () => {
    assert.equal(encode(Buffer.from('a'), { pad: false }), 'YQ');
  });

  test('encode accepts Uint8Array', () => {
    assert.equal(encode(new Uint8Array([104, 105])), 'aGk');
  });

  test('encode empty → empty', () => {
    assert.equal(encode(Buffer.alloc(0)), '');
  });

  test('decode roundtrip (unpadded)', () => {
    const src = Buffer.from('hello, world!');
    assert.deepEqual(decode(encode(src)), src);
  });

  test('decode tolerates padding on input', () => {
    assert.deepEqual(decode('YQ=='), Buffer.from('a'));
    assert.deepEqual(decode('YQ'), Buffer.from('a'));
    assert.deepEqual(decode('YWJj'), Buffer.from('abc'));
  });

  test('uses the URL-unsafe alphabet (+ and /)', () => {
    const bytes = Buffer.from([0xfb, 0xff]);
    assert.equal(encode(bytes), '+/8');
  });
});
