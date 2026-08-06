/**
 * Authenticator-data flag decoding + policy enforcement helpers.
 *
 * Layout: WebAuthn Level 3 §6.1 defines a single flag byte inside
 * the authenticator data with the following bits:
 *
 *   bit 0 (UP)   User Present
 *   bit 2 (UV)   User Verified
 *   bit 3 (BE)   Backup Eligible  (added in L3)
 *   bit 4 (BS)   Backup State     (added in L3)
 *   bit 6 (AT)   Attested credential data included
 *   bit 7 (ED)   Extension data included
 *
 * Bits 1 and 5 are reserved.
 */

import { PasskeyError, ErrorCode } from '../errors.js';

export const FLAG_MASK = Object.freeze({
  UP: 0x01,
  UV: 0x04,
  BE: 0x08,
  BS: 0x10,
  AT: 0x40,
  ED: 0x80,
});

/**
 * @typedef {object} AuthFlags
 * @property {number} raw   The whole flag byte, for round-trip / debugging.
 * @property {boolean} up   User Present.
 * @property {boolean} uv   User Verified.
 * @property {boolean} be   Backup Eligible.
 * @property {boolean} bs   Backup State (backed up right now).
 * @property {boolean} at   Attested credential data included.
 * @property {boolean} ed   Extension data included.
 */

/**
 * Decode the flag byte into a structured record.
 *
 * @param {number} byte
 * @returns {AuthFlags}
 */
export function decodeFlags(byte) {
  if (!Number.isInteger(byte) || byte < 0 || byte > 0xff) {
    throw new PasskeyError(ErrorCode.INVALID_ARGUMENT, `flags: expected a byte (0..255), got ${byte}`);
  }
  return {
    raw: byte,
    up: (byte & FLAG_MASK.UP) !== 0,
    uv: (byte & FLAG_MASK.UV) !== 0,
    be: (byte & FLAG_MASK.BE) !== 0,
    bs: (byte & FLAG_MASK.BS) !== 0,
    at: (byte & FLAG_MASK.AT) !== 0,
    ed: (byte & FLAG_MASK.ED) !== 0,
  };
}

/**
 * Derive a device-type label from the BE flag. Follows the
 * WebAuthn L3 §6.1.3 convention adopted by browsers and MDS —
 * BE=1 means the credential is eligible for syncing across
 * devices (a "multiDevice" passkey); BE=0 means it lives on
 * one authenticator only.
 *
 * @param {AuthFlags} flags
 * @returns {'singleDevice' | 'multiDevice'}
 */
export function deviceTypeFromFlags(flags) {
  return flags.be ? 'multiDevice' : 'singleDevice';
}

/**
 * Enforce user-presence / verification / backup policies against
 * decoded flags. Throws a `PasskeyError` with the code that matches
 * the violated bit — callers can distinguish `USER_VERIFICATION_REQUIRED`
 * from `BACKUP_ELIGIBLE_REQUIRED` without string-matching messages.
 *
 * `up` is always required — WebAuthn spec §7.1 step 15 and §7.2 step
 * 17 both mandate it. The rest are opt-in.
 *
 * @param {AuthFlags} flags
 * @param {object} [policy]
 * @param {boolean} [policy.requireUserVerification]
 * @param {boolean} [policy.requireBackupEligible]
 * @param {boolean} [policy.requireBackedUp]
 */
export function enforceFlags(flags, policy = {}) {
  if (!flags.up) {
    throw new PasskeyError(
      ErrorCode.USER_PRESENCE_REQUIRED,
      'flags: User Present bit (UP) is required and was not set',
    );
  }
  if (policy.requireUserVerification && !flags.uv) {
    throw new PasskeyError(
      ErrorCode.USER_VERIFICATION_REQUIRED,
      'flags: User Verification required but UV bit not set',
    );
  }
  if (policy.requireBackupEligible && !flags.be) {
    throw new PasskeyError(
      ErrorCode.BACKUP_ELIGIBLE_REQUIRED,
      'flags: backup-eligible credential required but BE bit not set',
    );
  }
  if (policy.requireBackedUp && !flags.bs) {
    throw new PasskeyError(ErrorCode.BACKED_UP_REQUIRED, 'flags: backed-up state required but BS bit not set');
  }
  // Spec sanity: BS=1 implies BE=1 (a credential can't be backed
  // up without being eligible for backup). WebAuthn L3 §6.1.3.
  if (flags.bs && !flags.be) {
    throw new PasskeyError(ErrorCode.AUTH_DATA_INVALID, 'flags: BS=1 with BE=0 is not a valid combination');
  }
}
