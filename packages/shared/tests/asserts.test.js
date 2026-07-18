import { describe, test } from 'node:test';
import assert from 'node:assert/strict';

import {
  assertBytesOrString,
  assertEncoding,
  assertNonNegativeInt,
  assertObject,
  assertOptionalObject,
  assertPositiveInt,
  assertString,
  assertUint48,
} from '../src/asserts.js';

describe('assertPositiveInt', () => {
  test('accepts positive integers', () => {
    for (const v of [1, 2, 100, Number.MAX_SAFE_INTEGER]) {
      assert.doesNotThrow(() => assertPositiveInt(v, 'x'));
    }
  });

  test('rejects zero, negatives, floats, unsafe, non-numbers', () => {
    for (const v of [0, -1, 1.5, 'nope', null, undefined, Number.MAX_SAFE_INTEGER + 1, NaN]) {
      assert.throws(() => assertPositiveInt(v, 'x'));
    }
  });

  test('error message includes the argument name', () => {
    assert.throws(() => assertPositiveInt(-1, 'options.iterations'), /options\.iterations must be a positive integer/);
  });
});

describe('assertNonNegativeInt', () => {
  test('accepts 0 and positive', () => {
    for (const v of [0, 1, 100]) assert.doesNotThrow(() => assertNonNegativeInt(v, 'x'));
  });

  test('rejects negative + non-int', () => {
    for (const v of [-1, 1.5, NaN, 'x']) assert.throws(() => assertNonNegativeInt(v, 'x'));
  });
});

describe('assertUint48', () => {
  test('accepts 0..2^48-1', () => {
    assert.doesNotThrow(() => assertUint48(0, 'ms'));
    assert.doesNotThrow(() => assertUint48(0xffffffffffff, 'ms'));
  });

  test('rejects out-of-range', () => {
    assert.throws(() => assertUint48(-1, 'ms'));
    assert.throws(() => assertUint48(0x1000000000000, 'ms'));
  });
});

describe('assertString', () => {
  test('accepts strings incl. empty', () => {
    assert.doesNotThrow(() => assertString('', 'x'));
    assert.doesNotThrow(() => assertString('hi', 'x'));
  });
  test('rejects non-strings', () => {
    for (const v of [42, null, undefined, {}, []]) {
      assert.throws(() => assertString(v, 'x'));
    }
  });
});

describe('assertObject / assertOptionalObject', () => {
  test('accepts plain objects; rejects null, arrays, primitives', () => {
    assert.doesNotThrow(() => assertObject({}, 'x'));
    assert.throws(() => assertObject(null, 'x'));
    assert.throws(() => assertObject([], 'x'));
    assert.throws(() => assertObject(42, 'x'));
  });

  test('optional variant skips undefined', () => {
    assert.doesNotThrow(() => assertOptionalObject(undefined, 'x'));
    assert.throws(() => assertOptionalObject(null, 'x'));
  });
});

describe('assertBytesOrString', () => {
  test('accepts string / Buffer / Uint8Array', () => {
    assert.doesNotThrow(() => assertBytesOrString('hi', 'x'));
    assert.doesNotThrow(() => assertBytesOrString(Buffer.from('hi'), 'x'));
    assert.doesNotThrow(() => assertBytesOrString(new Uint8Array(3), 'x'));
  });
  test('rejects other', () => {
    assert.throws(() => assertBytesOrString(42, 'x'));
    assert.throws(() => assertBytesOrString({}, 'x'));
    assert.throws(() => assertBytesOrString(null, 'x'));
  });
});

describe('assertEncoding', () => {
  test('default allows buffer', () => {
    for (const e of ['hex', 'base64', 'base64url', 'buffer']) {
      assert.doesNotThrow(() => assertEncoding(e, 'enc'));
    }
  });

  test('allowBuffer: false rejects buffer', () => {
    assert.throws(() => assertEncoding('buffer', 'enc', { allowBuffer: false }));
    assert.doesNotThrow(() => assertEncoding('hex', 'enc', { allowBuffer: false }));
  });

  test('rejects unknown encoding', () => {
    assert.throws(() => assertEncoding('utf8', 'enc'));
    assert.throws(() => assertEncoding(42, 'enc'));
  });
});
