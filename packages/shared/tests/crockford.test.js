import { describe, test } from 'node:test';
import assert from 'node:assert/strict';

import { ALPHABET, encode, decode } from '../src/crockford.js';

describe('crockford', () => {
  test('ALPHABET is the canonical 32-char string', () => {
    assert.equal(ALPHABET, '0123456789ABCDEFGHJKMNPQRSTVWXYZ');
    assert.equal(ALPHABET.length, 32);
  });

  test('encode: empty input → empty string', () => {
    assert.equal(encode(Buffer.alloc(0)), '');
  });

  test('encode: known vectors', () => {
    assert.equal(encode(Buffer.from([0x00, 0xff])), '03ZG');
    assert.equal(encode(Buffer.from('Hello')), '91JPRV3F');
  });

  test('encode: rejects non-bytes', () => {
    assert.throws(() => encode('nope'), TypeError);
    assert.throws(() => encode(null), TypeError);
    assert.throws(() => encode(42), TypeError);
  });

  test('decode: roundtrip', () => {
    const bytes = Buffer.from('Hello, Crockford!');
    assert.deepEqual(decode(encode(bytes)), bytes);
  });

  test('decode: case-insensitive', () => {
    assert.deepEqual(decode('91jprv3f'), Buffer.from('Hello'));
    assert.deepEqual(decode('91JPRV3F'), Buffer.from('Hello'));
  });

  test('decode: check aliases (I/L → 1, O → 0)', () => {
    assert.deepEqual(decode('I'), decode('1'));
    assert.deepEqual(decode('l'), decode('1'));
    assert.deepEqual(decode('O'), decode('0'));
  });

  test('decode: rejects non-string', () => {
    assert.throws(() => decode(Buffer.from('hi')), TypeError);
  });

  test('decode: rejects U (removed to prevent profanity)', () => {
    assert.throws(() => decode('91JPRU3F'), /non-Crockford character/);
  });

  test('decode: rejects check symbols', () => {
    for (const c of ['*', '~', '$', '=']) {
      assert.throws(() => decode(`91JPRV${c}`), /non-Crockford character/);
    }
  });

  test('decode: empty string → empty buffer', () => {
    assert.deepEqual(decode(''), Buffer.alloc(0));
  });
});
