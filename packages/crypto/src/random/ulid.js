import crypto from 'node:crypto';
import { assertUint48 } from '../internal/validate.js';
import { CROCKFORD as ALPHABET } from '../internal/alphabets.js';

/** Matches a 26-char ULID, case-insensitive. Character class excludes `I`, `L`, `O`, `U`. */
const ULID_RE = /^[0-9A-HJKMNP-TV-Z]{26}$/i;

/** 80-bit random field mask — used for overflow detection when incrementing. */
const RANDOM_MAX = 0xffffffffffffffffffffn; // 20 hex digits = 80 bits

// Module-level monotonic state — see uuid7 for the rationale (per-process
// strict ordering within a millisecond).
let _lastMs = -1;
let _lastRandom = 0n;

/**
 * Read 10 random bytes as an 80-bit BigInt (big-endian).
 * @private
 * @param {Buffer} bytes  Must be at least 10 bytes long.
 * @returns {bigint}
 */
function _readRandom80(bytes) {
  let n = 0n;
  for (let i = 0; i < 10; i++) {
    n = (n << 8n) | BigInt(bytes[i]);
  }
  return n;
}

/**
 * Encode a 48-bit integer timestamp as 10 Crockford base32 chars.
 * @private
 * @param {number} ts  Unix ms, 0 ≤ ts ≤ 2^48 − 1.
 * @returns {string}
 */
function _encodeTime(ts) {
  let out = '';
  for (let i = 0; i < 10; i++) {
    out = ALPHABET[ts % 32] + out;
    ts = Math.floor(ts / 32);
  }
  return out;
}

/**
 * Encode an 80-bit BigInt as 16 Crockford base32 chars.
 * @private
 * @param {bigint} n
 * @returns {string}
 */
function _encodeRandom(n) {
  let out = '';
  for (let i = 0; i < 16; i++) {
    out = ALPHABET[Number(n & 0x1fn)] + out;
    n >>= 5n;
  }
  return out;
}

/**
 * @param {number} [time]  Optional override timestamp in Unix milliseconds (UTC).
 *                         Must be a non-negative safe integer ≤ 2^48 − 1.
 *                         Defaults to `Date.now()`. Use `date.getTime()` for a `Date`.
 * @returns {string}       26-char uppercase Crockford base32 ULID.
 * @throws {CryptoError}   With code `INVALID_ARGUMENT` if `time` is provided but
 *                         is not a non-negative integer within the 48-bit range.
 * @see https://github.com/ulid/spec
 */
export function ulid(time) {
  if (time !== undefined) {
    assertUint48(time, 'time');
  }

  let ts;
  let rnd;

  if (time !== undefined) {
    // Explicit timestamp — pure output, monotonic state untouched.
    ts = time;
    rnd = _readRandom80(crypto.randomBytes(10));
  } else {
    const now = Date.now();
    if (now > _lastMs) {
      _lastMs = now;
      _lastRandom = _readRandom80(crypto.randomBytes(10));
    } else {
      // Same ms OR system clock regression — increment the 80-bit tail.
      _lastRandom += 1n;
      if (_lastRandom > RANDOM_MAX) {
        // 80-bit overflow (astronomically unlikely within a single ms — would
        // require > 2^80 calls) — bump ms and re-roll.
        _lastMs += 1;
        _lastRandom = _readRandom80(crypto.randomBytes(10));
      }
    }
    ts = _lastMs;
    rnd = _lastRandom;
  }

  return _encodeTime(ts) + _encodeRandom(rnd);
}

/**
 * @param {unknown} value
 * @returns {boolean}
 */
export function isULID(value) {
  return typeof value === 'string' && ULID_RE.test(value);
}
