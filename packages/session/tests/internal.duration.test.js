import { describe, test } from 'node:test';
import assert from 'node:assert/strict';

import { parseDuration } from '../src/internal/duration.js';
import { SessionError, ErrorCode } from '../src/errors.js';

describe('session internal parseDuration', () => {
  test('bare number = seconds → ms', () => {
    assert.equal(parseDuration(900), 900_000);
  });

  test('duration string with unit resolves via shared parser', () => {
    assert.equal(parseDuration('15m'), 15 * 60_000);
    assert.equal(parseDuration('500ms'), 500);
    assert.equal(parseDuration('1h'), 60 * 60_000);
  });

  test('rejects bare-numeric strings (unambiguous unit)', () => {
    for (const bad of ['900', ' 900 ', '900.0', '-900']) {
      assert.throws(
        () => parseDuration(bad),
        err => err instanceof SessionError && err.code === ErrorCode.INVALID_ARGUMENT && /ambiguous/.test(err.message),
      );
    }
  });

  test('rejects zero / negative / non-integer numbers', () => {
    for (const bad of [0, -1, 1.5, NaN, Infinity]) {
      assert.throws(
        () => parseDuration(bad),
        err => err instanceof SessionError && err.code === ErrorCode.INVALID_ARGUMENT,
      );
    }
  });

  test('rejects non-string / non-number inputs', () => {
    for (const bad of [null, undefined, {}, [], true]) {
      assert.throws(
        () => parseDuration(bad),
        err => err instanceof SessionError && err.code === ErrorCode.INVALID_ARGUMENT,
      );
    }
  });

  test('rejects malformed duration strings', () => {
    assert.throws(
      () => parseDuration('nope'),
      err => err instanceof SessionError && err.code === ErrorCode.INVALID_ARGUMENT,
    );
  });
});
