import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { FLAG_MASK, decodeFlags, deviceTypeFromFlags, enforceFlags } from '../../src/webauthn/flags.js';
import { PasskeyError, ErrorCode } from '../../src/errors.js';

function isPasskeyError(code) {
  return err => err instanceof PasskeyError && err.code === code;
}

describe('flags — decodeFlags', () => {
  test('all zero → all false', () => {
    const f = decodeFlags(0x00);
    assert.deepEqual(
      { up: f.up, uv: f.uv, be: f.be, bs: f.bs, at: f.at, ed: f.ed },
      { up: false, uv: false, be: false, bs: false, at: false, ed: false },
    );
    assert.equal(f.raw, 0);
  });

  test('UP | UV | AT (0x45) matches typical registration', () => {
    const f = decodeFlags(0x45);
    assert.equal(f.up, true);
    assert.equal(f.uv, true);
    assert.equal(f.at, true);
    assert.equal(f.be, false);
    assert.equal(f.bs, false);
    assert.equal(f.ed, false);
  });

  test('UP | UV | BE | BS (0x1d) matches a synced backed-up passkey auth', () => {
    const f = decodeFlags(0x1d);
    assert.equal(f.up, true);
    assert.equal(f.uv, true);
    assert.equal(f.be, true);
    assert.equal(f.bs, true);
  });

  test('all bits set (0xff)', () => {
    const f = decodeFlags(0xff);
    for (const flag of ['up', 'uv', 'be', 'bs', 'at', 'ed']) {
      assert.equal(f[flag], true, `${flag} should be set`);
    }
  });

  test('mask constants match WebAuthn L3 §6.1', () => {
    assert.equal(FLAG_MASK.UP, 0x01);
    assert.equal(FLAG_MASK.UV, 0x04);
    assert.equal(FLAG_MASK.BE, 0x08);
    assert.equal(FLAG_MASK.BS, 0x10);
    assert.equal(FLAG_MASK.AT, 0x40);
    assert.equal(FLAG_MASK.ED, 0x80);
  });

  test('rejects out-of-range values', () => {
    assert.throws(() => decodeFlags(-1), /expected a byte/);
    assert.throws(() => decodeFlags(256), /expected a byte/);
    assert.throws(() => decodeFlags(1.5), /expected a byte/);
    assert.throws(() => decodeFlags('0'), /expected a byte/);
  });
});

describe('flags — deviceTypeFromFlags', () => {
  test('BE=1 → multiDevice (syncable passkey)', () => {
    assert.equal(deviceTypeFromFlags(decodeFlags(0x08)), 'multiDevice');
  });

  test('BE=0 → singleDevice (hardware-bound)', () => {
    assert.equal(deviceTypeFromFlags(decodeFlags(0x00)), 'singleDevice');
  });
});

describe('flags — enforceFlags', () => {
  test('accepts UP alone by default', () => {
    enforceFlags(decodeFlags(0x01));
  });

  test('rejects when UP is missing → USER_PRESENCE_REQUIRED', () => {
    assert.throws(() => enforceFlags(decodeFlags(0x00)), isPasskeyError(ErrorCode.USER_PRESENCE_REQUIRED));
  });

  test('requireUserVerification rejects UP-only → USER_VERIFICATION_REQUIRED', () => {
    assert.throws(
      () => enforceFlags(decodeFlags(0x01), { requireUserVerification: true }),
      isPasskeyError(ErrorCode.USER_VERIFICATION_REQUIRED),
    );
  });

  test('requireUserVerification accepts UP+UV', () => {
    enforceFlags(decodeFlags(0x05), { requireUserVerification: true });
  });

  test('requireBackupEligible rejects a non-syncable credential → BACKUP_ELIGIBLE_REQUIRED', () => {
    assert.throws(
      () => enforceFlags(decodeFlags(0x01), { requireBackupEligible: true }),
      isPasskeyError(ErrorCode.BACKUP_ELIGIBLE_REQUIRED),
    );
  });

  test('requireBackedUp rejects when BS=0 → BACKED_UP_REQUIRED', () => {
    assert.throws(
      () => enforceFlags(decodeFlags(0x09), { requireBackedUp: true }), // BE=1, BS=0
      isPasskeyError(ErrorCode.BACKED_UP_REQUIRED),
    );
  });

  test('BS=1 with BE=0 is a spec violation → AUTH_DATA_INVALID', () => {
    // 0x11 = UP + BS but no BE — impossible per L3 §6.1.3.
    assert.throws(() => enforceFlags(decodeFlags(0x11)), isPasskeyError(ErrorCode.AUTH_DATA_INVALID));
  });
});
