import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { PasskeyError, ErrorCode } from '../src/index.js';

describe('@exortek/passkey — scaffold smoke', () => {
  test('exports PasskeyError + ErrorCode', () => {
    assert.equal(typeof PasskeyError, 'function');
    assert.equal(ErrorCode.INVALID_ARGUMENT, 'INVALID_ARGUMENT');
  });

  test('PasskeyError carries the invalid-argument code and 400 status', () => {
    const err = new PasskeyError(ErrorCode.INVALID_ARGUMENT, 'bad');
    assert.equal(err.code, ErrorCode.INVALID_ARGUMENT);
    assert.equal(err.status, 400);
  });
});
