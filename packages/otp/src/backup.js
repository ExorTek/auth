import { randomBytes } from 'node:crypto';
import { timingSafeEqual } from '@exortek/shared/timing-safe';
import { ALPHABET as CROCKFORD_ALPHABET } from '@exortek/shared/crockford';
import { OtpError, ErrorCode } from './internal/errors.js';

/**
 * Ready-made shapes for the most common backup-code conventions.
 * Spread into `backupCodes` options to pick one, override individual
 * fields to tweak.
 *
 *   backupCodes(10, backupPresets.numeric)
 *   backupCodes(10, { ...backupPresets.long, groups: 3 })
 *
 * @type {Readonly<Record<'crockford' | 'numeric' | 'long' | 'hex' | 'short', BackupCodesOptions>>}
 */
export const backupPresets = Object.freeze({
  /**
   * Default — 10 unambiguous chars, dash-split into two groups of 5.
   * Matches the visual weight of a GitHub / Stripe recovery code.
   */
  crockford: Object.freeze({ length: 10, groups: 2, alphabet: CROCKFORD_ALPHABET }),

  /**
   * 8-digit numeric, split into 2 groups of 4 — Google's account
   * recovery code convention. Easiest to type on a mobile keypad.
   * Trades ~3 bits of entropy vs `crockford` for ergonomics.
   */
  numeric: Object.freeze({ length: 8, groups: 2, alphabet: '0123456789' }),

  /**
   * Enterprise-flavour recovery code — 12 unambiguous chars split into
   * 3 groups of 4 (`ABCD-EFGH-JKMN`). More entropy, more typing.
   */
  long: Object.freeze({ length: 12, groups: 3, alphabet: CROCKFORD_ALPHABET }),

  /**
   * 8-char hex, dash-split. Classic sysadmin look — `3F4A-9B2C`.
   */
  hex: Object.freeze({ length: 8, groups: 2, alphabet: '0123456789ABCDEF' }),

  /**
   * Small footprint — 6 unambiguous chars, ungrouped (`ABC7Y2`).
   * For low-friction recovery flows where the user reads codes off a
   * phone screen instead of a printed sheet. ~30 bits of entropy per
   * code; pair with rate-limiting.
   */
  short: Object.freeze({ length: 6, groups: 1, alphabet: CROCKFORD_ALPHABET }),
});

/**
 * @typedef {object} BackupCodesOptions
 * @property {number} [length=10]
 *   Total number of characters per code (excluding group separators).
 *   10 chars from a 32-symbol alphabet = 50 bits of entropy per code —
 *   comfortably beyond brute-force even with weak server-side hashing.
 * @property {number} [groups=2]
 *   How many dash-separated groups to visually split the code into
 *   for readability. Set to `1` to disable grouping.
 * @property {string} [alphabet]
 *   Override the character set. The default (Crockford Base32) skips
 *   the ambiguous `0/O/1/I/L` glyphs.
 */

/**
 * Generate a batch of one-time recovery codes.
 *
 * Codes are formatted like `ABCD-1234-EF` — dash-separated for easy
 * transcription from a paper printout, uppercase only, no ambiguous
 * characters.
 *
 * The caller is responsible for **hashing** the codes before storage
 * (bcrypt / argon2 / a strong HMAC keyed with a server secret — do
 * NOT store them raw). See the README for a worked example.
 *
 * @param {number} [n=10]                 How many codes to generate.
 * @param {BackupCodesOptions} [options]
 * @returns {string[]}
 */
export function backupCodes(n = 10, options = {}) {
  if (!Number.isInteger(n) || n < 1 || n > 100) {
    throw new OtpError(ErrorCode.INVALID_ARGUMENT, `backupCodes: n must be an integer in [1, 100]; got ${n}`);
  }
  const length = options.length ?? 10;
  const groups = options.groups ?? 2;
  const alphabet = options.alphabet ?? CROCKFORD_ALPHABET;

  if (!Number.isInteger(length) || length < 6 || length > 32) {
    throw new OtpError(ErrorCode.INVALID_ARGUMENT, `backupCodes: length must be an integer in [6, 32]; got ${length}`);
  }
  if (!Number.isInteger(groups) || groups < 1 || groups > length) {
    throw new OtpError(
      ErrorCode.INVALID_ARGUMENT,
      `backupCodes: groups must be an integer in [1, length]; got ${groups}`,
    );
  }
  if (typeof alphabet !== 'string' || alphabet.length < 8 || alphabet.length > 256) {
    throw new OtpError(ErrorCode.INVALID_ARGUMENT, 'backupCodes: alphabet must be a string of 8-256 unique characters');
  }

  const groupSize = Math.floor(length / groups);
  const remainder = length % groups;

  const out = [];
  for (let i = 0; i < n; i++) {
    const raw = draw(length, alphabet);
    if (groups === 1) {
      out.push(raw);
      continue;
    }
    // Distribute the remainder across the first N groups so no group is
    // notably shorter than the rest.
    const parts = [];
    let offset = 0;
    for (let g = 0; g < groups; g++) {
      const size = groupSize + (g < remainder ? 1 : 0);
      parts.push(raw.slice(offset, offset + size));
      offset += size;
    }
    out.push(parts.join('-'));
  }
  return out;
}

/**
 * Normalize a user-supplied code to the format `backupCodes` returns
 * so timing-safe compare works. Strips whitespace, uppercases, and
 * removes dashes.
 *
 * @param {string} input
 * @returns {string}
 */
export function normalizeBackupCode(input) {
  if (typeof input !== 'string') {
    return '';
  }
  return input.replace(/[\s-]+/g, '').toUpperCase();
}

/**
 * Timing-safe compare between a user-supplied code and a candidate.
 * Both sides are normalized first (whitespace / dashes / case).
 *
 * Use this to check the user's input against every unused stored code
 * *without* short-circuiting on mismatch length, so an attacker can't
 * distinguish "wrong format" from "wrong value" from timing.
 *
 * @param {string} candidate  What the user submitted.
 * @param {string} stored     One of the codes you saved at enrollment.
 * @returns {boolean}
 */
export function compareBackupCode(candidate, stored) {
  const a = normalizeBackupCode(candidate);
  const b = normalizeBackupCode(stored);
  if (a.length === 0 || b.length === 0) {
    return false;
  }
  // The shared compare is length-safe: a mismatch burns a comparison
  // instead of short-circuiting, so "wrong length" is not
  // distinguishable from "wrong value" via timing.
  return timingSafeEqual(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
}

/**
 * Timing-safe scan across a list of stored codes. Returns the index of
 * the first matching entry, or `null` when nothing matches. **Every**
 * entry is compared even after a match, so an attacker can't distinguish
 * "wrong code" from "wrong slot" through timing.
 *
 *   const idx = verifyBackupCode(userInput, user.backupCodes)
 *   if (idx === null) return res.status(401).end()
 *   await db.markBackupCodeUsed(userId, idx)   // single-use
 *
 * Store the codes **hashed** — bcrypt / argon2 / a strong keyed HMAC.
 * This helper hands off the compare to {@link compareBackupCode}, so
 * if your `storedList` is a list of plain strings the raw input is
 * matched against them directly; wire it into your hash routine
 * yourself when you're storing digests.
 *
 * @param {string} candidate       User-supplied code (any case / spacing).
 * @param {string[]} storedList    Your saved codes (in the order you
 *                                 want indices reported).
 * @returns {number | null}        Zero-based index of the match, or null.
 */
export function verifyBackupCode(candidate, storedList) {
  if (!Array.isArray(storedList) || storedList.length === 0) {
    return null;
  }
  let matchIndex = null;
  for (let i = 0; i < storedList.length; i++) {
    const eq = compareBackupCode(candidate, storedList[i]);
    if (eq && matchIndex === null) {
      matchIndex = i;
    }
  }
  return matchIndex;
}

// Rejection sampling — draw `length` chars uniformly from `alphabet`
// without introducing modulo bias. For a 32-char alphabet this is
// exact; for other sizes we retry the rare biased sample.
function draw(length, alphabet) {
  const chars = [...alphabet];
  const modulus = chars.length;
  const limit = 256 - (256 % modulus);
  const out = [];
  const buf = randomBytes(Math.max(64, length * 2));
  let idx = 0;
  while (out.length < length) {
    if (idx >= buf.length) {
      // Refill on the rare case we chewed through a huge chunk to
      // dodge bias — keeps the function allocation-frugal.
      buf.set(randomBytes(buf.length));
      idx = 0;
    }
    const b = buf[idx++];
    if (b < limit) {
      out.push(chars[b % modulus]);
    }
  }
  return out.join('');
}
