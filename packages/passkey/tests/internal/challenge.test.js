import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { base64url } from '@exortek/crypto/encode';
import { readIssuedJti } from '../../src/internal/challenge.js';
import { PasskeyError, ErrorCode } from '../../src/errors.js';

function b64u(obj) {
  return base64url.encode(new TextEncoder().encode(JSON.stringify(obj)));
}

describe('internal/challenge — readIssuedJti', () => {
  test('extracts jti from a well-shaped token', () => {
    const token = `chall.${b64u({ jti: 'abc123' })}.MAC`;
    assert.deepEqual(readIssuedJti(token), { jti: 'abc123' });
  });

  test('rejects tokens with the wrong number of segments', () => {
    assert.throws(
      () => readIssuedJti('only.two'),
      err => err instanceof PasskeyError && err.code === ErrorCode.CHALLENGE_INVALID,
    );
    assert.throws(
      () => readIssuedJti('one.two.three.four'),
      err => err instanceof PasskeyError && err.code === ErrorCode.CHALLENGE_INVALID,
    );
  });

  test('rejects payloads that are not valid UTF-8 JSON', () => {
    // Encode raw bytes that are not valid UTF-8 — the ff pair triggers
    // TextDecoder's fatal decode.
    const badPayload = base64url.encode(new Uint8Array([0xff, 0xff, 0xff]));
    assert.throws(
      () => readIssuedJti(`chall.${badPayload}.MAC`),
      err => err instanceof PasskeyError && err.code === ErrorCode.CHALLENGE_INVALID,
    );
  });

  test('rejects payloads without a jti string', () => {
    const noJti = `chall.${b64u({ other: 'field' })}.MAC`;
    assert.throws(
      () => readIssuedJti(noJti),
      err => err instanceof PasskeyError && err.code === ErrorCode.CHALLENGE_INVALID,
    );

    const emptyJti = `chall.${b64u({ jti: '' })}.MAC`;
    assert.throws(
      () => readIssuedJti(emptyJti),
      err => err instanceof PasskeyError && err.code === ErrorCode.CHALLENGE_INVALID,
    );
  });
});
