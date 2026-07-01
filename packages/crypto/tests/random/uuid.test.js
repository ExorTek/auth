import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  uuid4,
  uuid5,
  uuid7,
  isUUID,
  NAMESPACE_DNS,
  NAMESPACE_URL,
  NAMESPACE_OID,
  NAMESPACE_X500,
} from '../../src/index.js';
import { CryptoError, ErrorCode } from '../../src/errors.js';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

describe('uuid4', () => {
  it('returns a canonical 8-4-4-4-12 lowercase hex string', () => {
    const id = uuid4();
    assert.match(id, UUID_RE);
    assert.equal(id.length, 36);
  });

  it('sets the version nibble to 4', () => {
    const id = uuid4();
    assert.equal(id[14], '4'); // 15th char = version nibble
  });

  it('sets the variant bits to 10 (RFC 9562)', () => {
    // Variant is the high 2 bits of byte 8 (UUID char index 19).
    // Char must be one of 8, 9, a, b → high bit set, second bit clear.
    const id = uuid4();
    assert.match(id[19], /^[89ab]$/);
  });

  it('produces unique values on successive calls', () => {
    const set = new Set(Array.from({ length: 10_000 }, () => uuid4()));
    assert.equal(set.size, 10_000, 'expected 10k distinct UUIDs');
  });

  it('is recognised by isUUID', () => {
    assert.equal(isUUID(uuid4()), true);
  });
});

describe('uuid7', () => {
  it('returns a canonical 8-4-4-4-12 lowercase hex string', () => {
    const id = uuid7();
    assert.match(id, UUID_RE);
    assert.equal(id.length, 36);
  });

  it('sets the version nibble to 7', () => {
    assert.equal(uuid7()[14], '7');
  });

  it('sets the variant bits to 10 (RFC 9562)', () => {
    assert.match(uuid7()[19], /^[89ab]$/);
  });

  it('is strictly monotonic within the same millisecond', () => {
    // Generate 5000 IDs back-to-back; many should land in the same ms,
    // exercising the counter path. They must still sort in call order.
    const ids = Array.from({ length: 5000 }, () => uuid7());
    for (let i = 1; i < ids.length; i++) {
      assert.ok(ids[i] > ids[i - 1], `not monotonic at index ${i}: ${ids[i - 1]} >= ${ids[i]}`);
    }
  });

  it('is monotonic across millisecond boundaries (timestamp advances)', async () => {
    const a = uuid7();
    await new Promise(r => setTimeout(r, 5));
    const b = uuid7();
    assert.ok(b > a);
    // First 12 hex chars (after stripping the dash) encode the 48-bit timestamp;
    // b's timestamp must be strictly greater.
    const ts = s => parseInt(s.replace(/-/g, '').slice(0, 12), 16);
    assert.ok(ts(b) > ts(a));
  });

  it('honors an explicit time argument (backfill / event-time)', () => {
    const t = 1_700_000_000_000; // 2023-11-14T22:13:20Z
    const id = uuid7(t);
    // First 12 hex chars = 48-bit big-endian ms timestamp.
    const tsHex = id.replace(/-/g, '').slice(0, 12);
    assert.equal(parseInt(tsHex, 16), t);
  });

  it('rejects negative time', () => {
    assert.throws(
      () => uuid7(-1),
      err => {
        assert.ok(err instanceof CryptoError);
        assert.equal(err.code, ErrorCode.INVALID_ARGUMENT);
        return true;
      },
    );
  });

  it('rejects non-integer time', () => {
    assert.throws(
      () => uuid7(1.5),
      err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
    );
    assert.throws(
      () => uuid7(NaN),
      err => err instanceof CryptoError,
    );
    assert.throws(
      () => uuid7('1700000000000'),
      err => err instanceof CryptoError,
    );
  });

  it('rejects time beyond 48-bit range (2^48)', () => {
    assert.throws(
      () => uuid7(0xffffffffffff + 1),
      err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
    );
  });

  it('accepts time === 0 (Unix epoch)', () => {
    const id = uuid7(0);
    assert.match(id, UUID_RE);
    assert.equal(id.slice(0, 12), '00000000-000');
  });

  it('override path does not pollute monotonic state', () => {
    // Sandwich a far-future override between two default-path calls;
    // the default path must still advance monotonically from its own baseline.
    const a = uuid7();
    uuid7(Date.now() + 10_000_000); // jump far ahead via override
    const b = uuid7();
    assert.ok(b > a, 'default path should remain monotonic after override');
  });
});

describe('uuid5', () => {
  // RFC 9562 §A.4 test vectors.
  it('produces the canonical UUID for NAMESPACE_DNS + "www.example.com"', () => {
    assert.equal(uuid5(NAMESPACE_DNS, 'www.example.com'), '2ed6657d-e927-568b-95e1-2665a8aea6a2');
  });

  it('is deterministic — same input → same output', () => {
    const a = uuid5(NAMESPACE_DNS, 'user@example.com');
    const b = uuid5(NAMESPACE_DNS, 'user@example.com');
    assert.equal(a, b);
  });

  it('different names under the same namespace produce different UUIDs', () => {
    const a = uuid5(NAMESPACE_DNS, 'alice');
    const b = uuid5(NAMESPACE_DNS, 'bob');
    assert.notEqual(a, b);
  });

  it('different namespaces produce different UUIDs for the same name', () => {
    const a = uuid5(NAMESPACE_DNS, 'example');
    const b = uuid5(NAMESPACE_URL, 'example');
    assert.notEqual(a, b);
  });

  it('sets the version nibble to 5 and variant to 10', () => {
    const id = uuid5(NAMESPACE_DNS, 'check-bits');
    assert.equal(id[14], '5');
    assert.match(id[19], /^[89ab]$/);
  });

  it('returns canonical 8-4-4-4-12 format', () => {
    assert.match(uuid5(NAMESPACE_DNS, 'any'), UUID_RE);
  });

  it('accepts custom namespace UUIDs', () => {
    const customNs = uuid4(); // any well-formed UUID is a valid namespace
    const id = uuid5(customNs, 'name');
    assert.match(id, UUID_RE);
  });

  it('accepts uppercase namespace input', () => {
    const upper = NAMESPACE_DNS.toUpperCase();
    assert.equal(uuid5(upper, 'www.example.com'), uuid5(NAMESPACE_DNS, 'www.example.com'));
  });

  it('rejects malformed namespace', () => {
    assert.throws(
      () => uuid5('not-a-uuid', 'name'),
      err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
    );
    assert.throws(
      () => uuid5('', 'name'),
      err => err instanceof CryptoError,
    );
    assert.throws(
      () => uuid5(null, 'name'),
      err => err instanceof CryptoError,
    );
  });

  it('rejects non-string name', () => {
    assert.throws(
      () => uuid5(NAMESPACE_DNS, 123),
      err => err instanceof CryptoError && err.code === ErrorCode.INVALID_ARGUMENT,
    );
    assert.throws(
      () => uuid5(NAMESPACE_DNS, null),
      err => err instanceof CryptoError,
    );
    assert.throws(
      () => uuid5(NAMESPACE_DNS, undefined),
      err => err instanceof CryptoError,
    );
  });

  it('handles unicode names correctly', () => {
    const a = uuid5(NAMESPACE_DNS, 'café');
    const b = uuid5(NAMESPACE_DNS, 'café');
    assert.equal(a, b);
    assert.match(a, UUID_RE);
    // Should differ from the ASCII-equivalent without the accent.
    assert.notEqual(a, uuid5(NAMESPACE_DNS, 'cafe'));
  });

  it('handles empty name', () => {
    const id = uuid5(NAMESPACE_DNS, '');
    assert.match(id, UUID_RE);
    assert.equal(id[14], '5');
  });
});

describe('isUUID', () => {
  it('accepts the output of every uuid* function', () => {
    assert.equal(isUUID(uuid4()), true);
    assert.equal(isUUID(uuid7()), true);
    assert.equal(isUUID(uuid5(NAMESPACE_DNS, 'x')), true);
  });

  it('accepts the nil UUID', () => {
    assert.equal(isUUID('00000000-0000-0000-0000-000000000000'), true);
  });

  it('accepts uppercase hex', () => {
    assert.equal(isUUID('550E8400-E29B-41D4-A716-446655440000'), true);
  });

  it('rejects strings of the wrong shape', () => {
    assert.equal(isUUID(''), false);
    assert.equal(isUUID('not-a-uuid'), false);
    assert.equal(isUUID('550e8400-e29b-41d4-a716-44665544000'), false); // 1 char short
    assert.equal(isUUID('550e8400e29b41d4a716446655440000'), false); // missing dashes
    assert.equal(isUUID('550e8400-e29b-41d4-a716-44665544000g'), false); // non-hex
  });

  it('rejects non-string values', () => {
    assert.equal(isUUID(null), false);
    assert.equal(isUUID(undefined), false);
    assert.equal(isUUID(123), false);
    assert.equal(isUUID({}), false);
    assert.equal(isUUID([]), false);
    assert.equal(isUUID(true), false);
  });
});

describe('namespace constants', () => {
  it('exports the four RFC 9562 §6.6 namespace UUIDs', () => {
    assert.equal(NAMESPACE_DNS, '6ba7b810-9dad-11d1-80b4-00c04fd430c8');
    assert.equal(NAMESPACE_URL, '6ba7b811-9dad-11d1-80b4-00c04fd430c8');
    assert.equal(NAMESPACE_OID, '6ba7b812-9dad-11d1-80b4-00c04fd430c8');
    assert.equal(NAMESPACE_X500, '6ba7b814-9dad-11d1-80b4-00c04fd430c8');
  });

  it('are all valid UUIDs', () => {
    for (const ns of [NAMESPACE_DNS, NAMESPACE_URL, NAMESPACE_OID, NAMESPACE_X500]) {
      assert.equal(isUUID(ns), true);
    }
  });
});
