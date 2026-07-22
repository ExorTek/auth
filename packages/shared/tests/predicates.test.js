import { describe, test } from 'node:test';
import assert from 'node:assert/strict';

import {
  isObject,
  isString,
  isNonEmptyString,
  isFunction,
  isBytes,
  isNumber,
  isBoolean,
  isUndefined,
  isBigInt,
  isSymbol,
  isNull,
  isNullish,
  isArray,
  isBuffer,
  isUint8Array,
  isTrue,
  isFalse,
  isFiniteNumber,
  isInteger,
} from '../src/predicates.js';

describe('isObject', () => {
  test('plain objects pass', () => {
    assert.equal(isObject({}), true);
    assert.equal(isObject({ a: 1 }), true);
    assert.equal(isObject(Object.create(null)), true);
  });

  test('class instances pass — Node KeyObject shape, URL, user classes', () => {
    class Foo {}
    assert.equal(isObject(new Foo()), true);
    assert.equal(isObject(new URL('https://a.b')), true);
  });

  test('null, arrays, primitives all fail', () => {
    assert.equal(isObject(null), false);
    assert.equal(isObject(undefined), false);
    assert.equal(isObject([]), false);
    assert.equal(isObject([1, 2]), false);
    assert.equal(isObject(''), false);
    assert.equal(isObject('str'), false);
    assert.equal(isObject(0), false);
    assert.equal(isObject(42), false);
    assert.equal(isObject(true), false);
    assert.equal(isObject(false), false);
    assert.equal(isObject(Symbol('x')), false);
  });
});

describe('isString', () => {
  test('string primitives pass, everything else fails', () => {
    assert.equal(isString(''), true);
    assert.equal(isString('x'), true);
    assert.equal(isString(new String('x')), false); // boxed strings rejected
    assert.equal(isString(null), false);
    assert.equal(isString(undefined), false);
    assert.equal(isString(0), false);
    assert.equal(isString([]), false);
    assert.equal(isString({}), false);
  });
});

describe('isNonEmptyString', () => {
  test('empty string fails, non-empty passes, non-strings fail', () => {
    assert.equal(isNonEmptyString(''), false);
    assert.equal(isNonEmptyString('a'), true);
    assert.equal(isNonEmptyString('hello'), true);
    assert.equal(isNonEmptyString(null), false);
    assert.equal(isNonEmptyString(0), false);
  });
});

describe('isFunction', () => {
  test('functions of every flavour pass', () => {
    assert.equal(
      isFunction(() => {}),
      true,
    );
    assert.equal(
      isFunction(function () {}),
      true,
    );
    assert.equal(
      isFunction(async () => {}),
      true,
    );
    assert.equal(
      isFunction(function* () {}),
      true,
    );
    assert.equal(isFunction(class Foo {}), true);
    assert.equal(isFunction(Math.max), true);
  });

  test('non-functions fail', () => {
    assert.equal(isFunction(null), false);
    assert.equal(isFunction({}), false);
    assert.equal(isFunction('x'), false);
    assert.equal(isFunction(0), false);
  });
});

describe('isBytes', () => {
  test('Buffer and Uint8Array pass', () => {
    assert.equal(isBytes(Buffer.from('x')), true);
    assert.equal(isBytes(Buffer.alloc(0)), true);
    assert.equal(isBytes(new Uint8Array()), true);
    assert.equal(isBytes(new Uint8Array([1, 2, 3])), true);
  });

  test('strings and other typed arrays fail', () => {
    assert.equal(isBytes(''), false);
    assert.equal(isBytes('deadbeef'), false);
    assert.equal(isBytes(new Uint16Array()), false);
    assert.equal(isBytes(new ArrayBuffer(8)), false);
    assert.equal(isBytes([1, 2, 3]), false);
    assert.equal(isBytes(null), false);
  });
});

describe('isNumber', () => {
  test('finite and infinite numbers pass; NaN is rejected', () => {
    assert.equal(isNumber(0), true);
    assert.equal(isNumber(-42), true);
    assert.equal(isNumber(1.5), true);
    assert.equal(isNumber(Infinity), true);
    assert.equal(isNumber(-Infinity), true);
    assert.equal(isNumber(NaN), false);
    assert.equal(isNumber('5'), false);
    assert.equal(isNumber(null), false);
    assert.equal(isNumber(1n), false);
  });
});

describe('isFiniteNumber', () => {
  test('rejects NaN AND infinities', () => {
    assert.equal(isFiniteNumber(0), true);
    assert.equal(isFiniteNumber(-1.5), true);
    assert.equal(isFiniteNumber(NaN), false);
    assert.equal(isFiniteNumber(Infinity), false);
    assert.equal(isFiniteNumber(-Infinity), false);
    assert.equal(isFiniteNumber('5'), false);
  });
});

describe('isInteger', () => {
  test('safe integers pass; floats / NaN / Infinity / bigints fail', () => {
    assert.equal(isInteger(0), true);
    assert.equal(isInteger(-42), true);
    assert.equal(isInteger(Number.MAX_SAFE_INTEGER), true);
    assert.equal(isInteger(Number.MAX_SAFE_INTEGER + 1), false);
    assert.equal(isInteger(1.5), false);
    assert.equal(isInteger(NaN), false);
    assert.equal(isInteger(Infinity), false);
    assert.equal(isInteger(1n), false);
  });
});

describe('isBoolean', () => {
  test('true and false pass; truthy/falsy values do not', () => {
    assert.equal(isBoolean(true), true);
    assert.equal(isBoolean(false), true);
    assert.equal(isBoolean(0), false);
    assert.equal(isBoolean(1), false);
    assert.equal(isBoolean(''), false);
    assert.equal(isBoolean(null), false);
    assert.equal(isBoolean(undefined), false);
  });
});

describe('isTrue / isFalse', () => {
  test('exact-match — no truthy/falsy coercion', () => {
    assert.equal(isTrue(true), true);
    assert.equal(isTrue(1), false);
    assert.equal(isTrue('true'), false);
    assert.equal(isFalse(false), true);
    assert.equal(isFalse(0), false);
    assert.equal(isFalse(''), false);
    assert.equal(isFalse(null), false);
  });
});

describe('isUndefined / isNull / isNullish', () => {
  test('isUndefined only matches undefined', () => {
    assert.equal(isUndefined(undefined), true);
    assert.equal(isUndefined(null), false);
    assert.equal(isUndefined(0), false);
    assert.equal(isUndefined(''), false);
  });
  test('isNull only matches null', () => {
    assert.equal(isNull(null), true);
    assert.equal(isNull(undefined), false);
    assert.equal(isNull(0), false);
  });
  test('isNullish matches null AND undefined', () => {
    assert.equal(isNullish(null), true);
    assert.equal(isNullish(undefined), true);
    assert.equal(isNullish(0), false);
    assert.equal(isNullish(''), false);
    assert.equal(isNullish(false), false);
  });
});

describe('isBigInt / isSymbol', () => {
  test('primitives pass, everything else fails', () => {
    assert.equal(isBigInt(1n), true);
    assert.equal(isBigInt(BigInt(0)), true);
    assert.equal(isBigInt(1), false);
    assert.equal(isSymbol(Symbol('x')), true);
    assert.equal(isSymbol(Symbol.iterator), true);
    assert.equal(isSymbol('sym'), false);
  });
});

describe('isArray', () => {
  test('arrays pass; array-likes and typed arrays fail', () => {
    assert.equal(isArray([]), true);
    assert.equal(isArray([1, 2]), true);
    assert.equal(isArray(new Array(3)), true);
    assert.equal(isArray(new Uint8Array()), false);
    assert.equal(isArray({ length: 0 }), false);
    assert.equal(isArray('abc'), false);
  });
});

describe('isBuffer / isUint8Array', () => {
  test('isBuffer accepts Buffer only, not plain Uint8Array', () => {
    assert.equal(isBuffer(Buffer.from('x')), true);
    assert.equal(isBuffer(new Uint8Array([1, 2])), false);
    assert.equal(isBuffer(''), false);
  });
  test('isUint8Array accepts both Buffer and plain Uint8Array', () => {
    assert.equal(isUint8Array(Buffer.from('x')), true);
    assert.equal(isUint8Array(new Uint8Array()), true);
    assert.equal(isUint8Array(new Uint16Array()), false);
    assert.equal(isUint8Array(new ArrayBuffer(8)), false);
  });
});
