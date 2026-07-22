import { describe, test } from 'node:test';
import assert from 'node:assert/strict';

import { isObject, isString, isNonEmptyString, isFunction, isBytes } from '../src/predicates.js';

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
    assert.equal(isFunction(() => {}), true);
    assert.equal(isFunction(function () {}), true);
    assert.equal(isFunction(async () => {}), true);
    assert.equal(isFunction(function* () {}), true);
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
