import { randomBytes, pbkdf2 as pbkdf2Cb } from 'node:crypto';
import { promisify } from 'node:util';
import { timingSafeEqual } from '@exortek/shared/timing-safe';
import { PasswordError, ErrorCode } from '../errors.js';
import { assertPositiveInt } from '../internal/guards.js';
import { normalizePassword } from '../internal/normalize.js';
import { parseHash, serialiseHash } from '../phc.js';

const pbkdf2Async = promisify(pbkdf2Cb);

// OWASP Password Storage Cheat Sheet (2024):
//   PBKDF2-HMAC-SHA256 → 600,000 iterations
//   PBKDF2-HMAC-SHA512 → 210,000 iterations
// PBKDF2 is not memory-hard — reach for it only when FIPS / NIST
// compliance is a hard requirement, otherwise prefer scrypt or argon2id.
const DEFAULTS = Object.freeze({
  hash: 'sha256',
  iterations: 600_000,
  keyLength: 32,
  saltLength: 16,
});

const HASH_ITERATIONS = Object.freeze({
  sha256: 600_000,
  sha512: 210_000,
});

const SUPPORTED_HASHES = new Set(['sha256', 'sha512']);

// Sanity ceiling on iterations read back from a stored PHC hash. A
// poisoned row with i=10^9 would otherwise turn every login attempt
// into a multi-second CPU DoS. 10M covers OWASP's outer target by ~16×
// and still returns in well under a second on commodity hardware.
const MAX_VERIFY_ITERATIONS = 10_000_000;

/**
 * @typedef {'sha256' | 'sha512'} Pbkdf2HashName
 */

/**
 * @typedef {object} Pbkdf2HashOptions
 * @property {Pbkdf2HashName} [hash='sha256']
 * @property {number} [iterations]           OWASP 2024: 600k for sha256, 210k for sha512.
 * @property {number} [keyLength=32]         Output length in bytes.
 * @property {number} [saltLength=16]        Random salt length. 16 bytes = 128 bits.
 * @property {Buffer} [salt]                 Pre-generated salt (KAT vectors only).
 */

/**
 * @typedef {object} Pbkdf2RehashCheck
 * @property {Pbkdf2HashName} [hash]
 * @property {number} [iterations]
 * @property {number} [keyLength]
 */

/** Immutable defaults for {@link needsRehash} and preset consumers. */
export const pbkdf2Defaults = DEFAULTS;
export const pbkdf2OwaspIterations = HASH_ITERATIONS;

/**
 * Hash a password with PBKDF2-HMAC (RFC 8018 §5.2). Emits a
 * self-describing PHC string:
 *
 *   $pbkdf2-sha256$i=600000$<b64-salt>$<b64-hash>
 *
 * PBKDF2 is a CPU-only KDF — an attacker with a GPU wins the arms race
 * against you. Only choose this over scrypt/argon2 when FIPS compliance
 * or a legacy environment forces your hand.
 *
 * @param {string | Buffer | Uint8Array} password
 * @param {Pbkdf2HashOptions} [options]
 * @returns {Promise<string>}
 */
export async function hash(password, options = {}) {
  const hashName = options.hash ?? DEFAULTS.hash;
  assertHash(hashName);
  const iterations = options.iterations ?? HASH_ITERATIONS[hashName];
  const keyLength = options.keyLength ?? DEFAULTS.keyLength;
  const saltLength = options.saltLength ?? DEFAULTS.saltLength;
  assertPositiveInt(iterations, 'pbkdf2.options.iterations');
  assertPositiveInt(keyLength, 'pbkdf2.options.keyLength');
  assertPositiveInt(saltLength, 'pbkdf2.options.saltLength');

  const pwBytes = normalizePassword(password);
  const salt = options.salt ?? randomBytes(saltLength);
  const derived = await pbkdf2Async(pwBytes, salt, iterations, keyLength, hashName);
  return serialiseHash({
    algorithm: `pbkdf2-${hashName}`,
    params: { i: iterations },
    salt,
    hash: derived,
  });
}

/**
 * Verify a candidate password against a PBKDF2 PHC hash in constant time.
 *
 * @param {string | Buffer | Uint8Array} password
 * @param {string} phcHash
 * @returns {Promise<boolean>}
 */
export async function verify(password, phcHash) {
  const record = parseHash(phcHash);
  if (
    !record ||
    (record.algorithm !== 'pbkdf2-sha256' && record.algorithm !== 'pbkdf2-sha512') ||
    !record.salt ||
    !record.hash
  ) {
    return false;
  }
  const hashName = record.algorithm === 'pbkdf2-sha256' ? 'sha256' : 'sha512';
  const iterations = Number(record.params.i);
  if (!Number.isInteger(iterations) || iterations < 1 || iterations > MAX_VERIFY_ITERATIONS) {
    return false;
  }
  let pwBytes;
  try {
    pwBytes = normalizePassword(password);
  } catch {
    return false;
  }
  const derived = await pbkdf2Async(pwBytes, record.salt, iterations, record.hash.length, hashName);
  return timingSafeEqual(derived, record.hash);
}

/**
 * @param {string} phcHash
 * @param {Pbkdf2RehashCheck} [target]
 * @returns {boolean}
 */
export function needsRehash(phcHash, target = {}) {
  const record = parseHash(phcHash);
  if (!record || (record.algorithm !== 'pbkdf2-sha256' && record.algorithm !== 'pbkdf2-sha512')) {
    return true;
  }
  const gotHash = record.algorithm === 'pbkdf2-sha256' ? 'sha256' : 'sha512';
  const wantHash = target.hash ?? DEFAULTS.hash;
  if (gotHash !== wantHash) {
    return true;
  }
  const wantIterations = target.iterations ?? HASH_ITERATIONS[wantHash];
  const wantKeyLength = target.keyLength ?? DEFAULTS.keyLength;
  const gotIterations = Number(record.params.i);
  const gotKeyLength = record.hash ? record.hash.length : 0;
  return gotIterations < wantIterations || gotKeyLength < wantKeyLength;
}

function assertHash(hashName) {
  if (!SUPPORTED_HASHES.has(hashName)) {
    throw new PasswordError(
      ErrorCode.UNSUPPORTED_ALGORITHM,
      `pbkdf2: hash must be one of ${[...SUPPORTED_HASHES].join(', ')}; got '${hashName}'`,
    );
  }
}
