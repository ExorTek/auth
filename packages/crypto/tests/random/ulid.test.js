import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { ulid, isULID } from '../../src/index.js';
import { CryptoError, ErrorCode } from '../../src/errors.js';

const ULID_RE = /^[0-9A-HJKMNP-TV-Z]{26}$/;
const CROCKFORD = /^[0-9A-HJKMNP-TV-Z]+$/;

describe('ulid', () => {
  it('returns a 26-character Crockford base32 string', () => {
    const id = ulid();
    assert.equal(id.length, 26);
    assert.match(id, ULID_RE);
  });

  it('never contains disallowed characters (I, L, O, U)', () => {
    for (let i = 0; i < 1000; i++) {
      const id = ulid();
      assert.doesNotMatch(id, /[ILOU]/, `illegal char in ${id}`);
      assert.match(id, CROCKFORD);
    }
  });

  it('is strictly monotonic within the same millisecond', () => {
    // 5000 back-to-back calls will hit the same-ms path many times.
    const ids = Array.from({ length: 5000 }, () => ulid());
    for (let i = 1; i < ids.length; i++) {
      assert.ok(ids[i] > ids[i - 1], `not monotonic at index ${i}: ${ids[i - 1]} >= ${ids[i]}`);
    }
  });

  it('is monotonic across millisecond boundaries', async () => {
    const a = ulid();
    await new Promise((r) => setTimeout(r, 5));
    const b = ulid();
    assert.ok(b > a);
    // First 10 chars = timestamp; b's timestamp portion must be strictly greater.
    assert.ok(b.slice(0, 10) > a.slice(0, 10));
  });

  it('produces unique values across many calls', () => {
    const set = new Set(Array.from({ length: 10_000 }, () => ulid()));
    assert.equal(set.size, 10_000);
  });

  it('honors an explicit time argument', () => {
    const t = 1_700_000_000_000; // 2023-11-14T22:13:20Z
    const id = ulid(t);
    // Decode the 10-char timestamp back and compare.
    const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
    let decoded = 0;
    for (const ch of id.slice(0, 10)) {
      decoded = decoded * 32 + ALPHABET.indexOf(ch);
    }
    assert.equal(decoded, t);
  });

  it('produces ulids at time=0 that sort before any modern time', () => {
    const past = ulid(0);
    const now = ulid();
    assert.ok(past < now);
    assert.equal(past.slice(0, 10), '0000000000');
  });

  it('rejects negative time', () => {
    assert.throws(
      () => ulid(-1),
      (err) => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
    );
  });

  it('rejects non-integer time', () => {
    assert.throws(() => ulid(1.5), (err) => err instanceof CryptoError);
    assert.throws(() => ulid(NaN), (err) => err instanceof CryptoError);
    assert.throws(() => ulid('not a number'), (err) => err instanceof CryptoError);
  });

  it('rejects time beyond 48-bit range', () => {
    assert.throws(
      () => ulid(0xffffffffffff + 1),
      (err) => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
    );
  });

  it('override path does not pollute monotonic state', () => {
    const a = ulid();
    ulid(Date.now() + 10_000_000); // jump far ahead via override
    const b = ulid();
    assert.ok(b > a, 'default path should remain monotonic after override');
  });

  it('is recognised by isULID', () => {
    assert.equal(isULID(ulid()), true);
    assert.equal(isULID(ulid(0)), true);
    assert.equal(isULID(ulid(1_700_000_000_000)), true);
  });
});

describe('isULID', () => {
  it('accepts well-formed ULIDs (uppercase and lowercase)', () => {
    const id = ulid();
    assert.equal(isULID(id), true);
    assert.equal(isULID(id.toLowerCase()), true);
  });

  it('rejects strings of the wrong length', () => {
    assert.equal(isULID(''), false);
    assert.equal(isULID('01ARZ3NDEKTSV4RRFFQ69G5FA'), false); // 25 chars
    assert.equal(isULID('01ARZ3NDEKTSV4RRFFQ69G5FAVX'), false); // 27 chars
  });

  it('rejects strings with disallowed characters', () => {
    assert.equal(isULID('01ARZ3NDEKTSV4RRFFQ69G5FAI'), false); // I
    assert.equal(isULID('01ARZ3NDEKTSV4RRFFQ69G5FAL'), false); // L
    assert.equal(isULID('01ARZ3NDEKTSV4RRFFQ69G5FAO'), false); // O
    assert.equal(isULID('01ARZ3NDEKTSV4RRFFQ69G5FAU'), false); // U
  });

  it('rejects non-string values', () => {
    assert.equal(isULID(null), false);
    assert.equal(isULID(undefined), false);
    assert.equal(isULID(123), false);
    assert.equal(isULID({}), false);
    assert.equal(isULID([]), false);
    assert.equal(isULID(true), false);
  });

  it('rejects UUIDs (different format)', () => {
    assert.equal(isULID('550e8400-e29b-41d4-a716-446655440000'), false);
  });
});
