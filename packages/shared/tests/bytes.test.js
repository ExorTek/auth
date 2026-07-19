import { describe, test } from 'node:test';
import assert from 'node:assert/strict';

import { toBuffer, toBufferWithEncoding } from '../src/bytes.js';

describe('toBuffer', () => {
  test('string → UTF-8 Buffer', () => {
    const buf = toBuffer('hello', 'v');
    assert.ok(Buffer.isBuffer(buf));
    assert.deepEqual(buf, Buffer.from('hello', 'utf8'));
  });

  test('Buffer → passed through (identity)', () => {
    const src = Buffer.from([1, 2, 3]);
    assert.equal(toBuffer(src, 'v'), src);
  });

  test('Uint8Array → Buffer wrapping same storage (no copy)', () => {
    const src = new Uint8Array([1, 2, 3]);
    const buf = toBuffer(src, 'v');
    assert.ok(Buffer.isBuffer(buf));
    assert.equal(buf.buffer, src.buffer);
    assert.equal(buf.byteOffset, src.byteOffset);
    assert.equal(buf.byteLength, src.byteLength);
  });

  test('argument name is included in the error message', () => {
    assert.throws(() => toBuffer(42, 'options.secret'), /options\.secret must be a string or Buffer/);
  });

  test('rejects other shapes', () => {
    for (const bad of [42, null, undefined, {}, [], true]) {
      assert.throws(() => toBuffer(bad, 'v'), /v must be a string or Buffer/);
    }
  });
});

describe('toBufferWithEncoding', () => {
  test('string decoded with the given encoding', () => {
    const hex = Buffer.from('deadbeef', 'hex').toString('hex');
    assert.deepEqual(toBufferWithEncoding(hex, 'v', 'hex'), Buffer.from('deadbeef', 'hex'));
    const b64 = Buffer.from('hi').toString('base64');
    assert.deepEqual(toBufferWithEncoding(b64, 'v', 'base64'), Buffer.from('hi'));
  });

  test('Buffer / Uint8Array pass through', () => {
    const src = Buffer.from([1, 2]);
    assert.equal(toBufferWithEncoding(src, 'v', 'hex'), src);
    const u8 = new Uint8Array([3, 4]);
    const wrapped = toBufferWithEncoding(u8, 'v', 'hex');
    assert.equal(wrapped.buffer, u8.buffer);
  });

  test('rejects other shapes', () => {
    for (const bad of [42, null, undefined, {}, []]) {
      assert.throws(() => toBufferWithEncoding(bad, 'v', 'hex'), /v must be a string or Buffer/);
    }
  });
});
