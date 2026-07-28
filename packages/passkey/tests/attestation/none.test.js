import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { verifyNone } from '../../src/attestation/none.js';
import { PasskeyError, ErrorCode } from '../../src/errors.js';

describe('none attestation', () => {
  test('accepts an empty attStmt map', () => {
    const out = verifyNone({ attStmt: new Map() });
    assert.deepEqual(out, { format: 'none', trustPath: 'no-anchor' });
  });

  test('rejects when attStmt is not a Map', () => {
    assert.throws(
      () => verifyNone({ attStmt: {} }),
      err => err instanceof PasskeyError && err.code === ErrorCode.ATTESTATION_INVALID,
    );
  });

  test('rejects when attStmt carries any field (spec: empty)', () => {
    const attStmt = new Map([['alg', -7]]);
    assert.throws(
      () => verifyNone({ attStmt }),
      err => err instanceof PasskeyError && err.code === ErrorCode.ATTESTATION_INVALID,
    );
  });
});
