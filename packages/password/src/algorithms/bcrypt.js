import { createHash } from 'node:crypto';

import { isBuffer } from '@exortek/shared/predicates';

import { PasswordError, ErrorCode } from '../errors.js';
import { normalizePassword } from '../internal/normalize.js';
import { parseHash } from '../phc.js';
import { invalidArgument } from '../internal/guards.js';

// OWASP Password Storage Cheat Sheet (2024): bcrypt is acceptable if
// argon2id / scrypt are unavailable. Work factor ≥ 10 is the floor;
// 12 is a common default on modern hardware and completes in ~200-300ms
// per verify. Anything above 14 gets uncomfortable for interactive
// logins.
const DEFAULTS = Object.freeze({
  rounds: 12,
  mode: 'prehash',
});

// The infamous 72-byte input limit of the original Blowfish key schedule.
// bcrypt silently truncates longer input; passwords beyond this length
// are mapped to their first-72-bytes prefix — meaning a 100-char password
// hashes identically to its first 72 chars. Three ways out:
//
//   'prehash'  — SHA-256 the password first, then bcrypt the hash. Every
//                byte contributes; standard practice in Django, Passlib,
//                Laravel. The default here.
//   'strict'   — Refuse passwords longer than 72 bytes. Safest, but the
//                caller has to reject the request explicitly at the API
//                layer.
//   'truncate' — Match bcrypt's own historical behaviour (silent truncate).
//                Included only so you can round-trip against hashes
//                produced by other libraries; do NOT choose this for new
//                deployments.
const BCRYPT_MAX_INPUT_BYTES = 72;
const BCRYPT_MAX_VERIFY_ROUNDS = 20;

/**
 * @typedef {'prehash' | 'strict' | 'truncate'} BcryptMode
 */

/**
 * @typedef {object} BcryptHashOptions
 * @property {number} [rounds=12]
 *   Work factor. Each +1 doubles the compute cost. 10 is the minimum
 *   OWASP will accept; 12 is a modern default; 14 pushes verify to
 *   ~1s on typical server hardware.
 * @property {BcryptMode} [mode='prehash']
 *   How to handle passwords longer than 72 bytes — see module notes.
 *   Default `'prehash'` (Django/Passlib/Laravel pattern) makes every
 *   byte contribute.
 */

/**
 * @typedef {object} BcryptRehashCheck
 * @property {number} [rounds=12]
 * @property {BcryptMode} [mode]         Rehash if the caller intends to
 *                                       migrate to a different mode; usually
 *                                       omitted.
 */

/** Immutable defaults for {@link needsRehash} and preset consumers. */
export const bcryptDefaults = DEFAULTS;

// See argon2.js for the same one-time-cache pattern.
let impl = null;
let probed = false;

async function loadBcrypt() {
  if (probed) {
    if (impl) {
      return impl;
    }
    throw missingPeerError();
  }
  try {
    const mod = await import('bcryptjs');
    impl = mod.default ?? mod;
  } catch (cause) {
    probed = true;
    throw missingPeerError(cause);
  }
  probed = true;
  return impl;
}

function missingPeerError(cause) {
  return new PasswordError(
    ErrorCode.MISSING_PEER_DEP,
    "@exortek/password's bcrypt backend requires the 'bcryptjs' npm package. Install it as a peer:\n\n  yarn add bcryptjs\n\nbcryptjs is pure JavaScript (no native build) and works on Alpine, serverless, and edge runtimes. If you'd rather not use bcrypt at all, scrypt (Node native) or argon2 (peer) are better choices for new deployments.",
    cause ? { cause } : undefined,
  );
}

/**
 * Prepare a password for bcrypt input honouring the configured `mode`.
 * Returns the exact string / buffer that gets passed to the bcrypt call.
 * Exported for tests; not part of the public API.
 * @private
 */
export function preparePasswordForBcrypt(bytes, mode) {
  if (bytes.length <= BCRYPT_MAX_INPUT_BYTES) {
    return bytes;
  }
  if (mode === 'prehash') {
    // SHA-256 → 32 bytes → base64 → 44 chars, comfortably within bcrypt's
    // 72-byte budget while collapsing arbitrary-length input into a
    // fixed-size domain. Encoding as base64 (rather than hex) keeps
    // more entropy per byte.
    return createHash('sha256').update(bytes).digest('base64');
  }
  if (mode === 'strict') {
    throw new PasswordError(
      ErrorCode.PASSWORD_TOO_LONG,
      `bcrypt rejects passwords over ${BCRYPT_MAX_INPUT_BYTES} bytes in 'strict' mode (input was ${bytes.length} bytes). Enable 'prehash' mode to allow arbitrary-length input, or use scrypt / argon2id which have no such limit.`,
      { details: { bytes: bytes.length, maxBytes: BCRYPT_MAX_INPUT_BYTES } },
    );
  }
  if (mode === 'truncate') {
    return bytes.subarray(0, BCRYPT_MAX_INPUT_BYTES);
  }
  throw invalidArgument(`bcrypt.options.mode must be 'prehash' | 'strict' | 'truncate'; got '${mode}'`);
}

/**
 * Hash a password with bcrypt via the `bcryptjs` npm package. Requires
 * the peer dependency; throws {@link PasswordError} with
 * `code: MISSING_PEER_DEP` and an actionable message if not installed.
 *
 * The returned string uses bcrypt's native format:
 *
 *   $2b$12$<22-char-salt><31-char-hash>
 *
 * **Note the 72-byte input limit** — see the `mode` option and the
 * module-level notes for how this package handles longer input.
 *
 * @param {string | Buffer | Uint8Array} password
 * @param {BcryptHashOptions} [options]
 * @returns {Promise<string>}
 */
export async function hash(password, options = {}) {
  const rounds = options.rounds ?? DEFAULTS.rounds;
  const mode = options.mode ?? DEFAULTS.mode;
  assertRounds(rounds);
  const pwBytes = normalizePassword(password);
  const prepared = preparePasswordForBcrypt(pwBytes, mode);
  const impl = await loadBcrypt();
  // bcryptjs 3.x expects a string; give it one. `prepared` is either a
  // Buffer (short input) or a base64 string (prehash mode) — normalise.
  return impl.hash(isBuffer(prepared) ? prepared.toString('utf8') : prepared, rounds);
}

/**
 * Verify a candidate password against a bcrypt hash. Returns `false` on
 * any mismatch, including malformed hashes and wrong algorithms.
 *
 * `mode` is **read from the caller's option** rather than being encoded
 * into the bcrypt string — bcrypt's format has no room for it. Pass the
 * same `mode` you used at hash time; the default `'prehash'` matches
 * this package's default.
 *
 * @param {string | Buffer | Uint8Array} password
 * @param {string} bcryptHash
 * @param {{ mode?: BcryptMode }} [options]
 * @returns {Promise<boolean>}
 */
export async function verify(password, bcryptHash, options = {}) {
  const record = parseHash(bcryptHash);
  if (!record || record.algorithm !== 'bcrypt') {
    return false;
  }
  // Cap `rounds` on the verify side. The bcrypt string format admits
  // rounds up to 31, meaning 2^31 Blowfish key-schedule iterations
  // computed synchronously in pure-JS bcryptjs — a single poisoned
  // stored hash can hang the process indefinitely. 20 is well above
  // the OWASP-2024 minimum of 10 and the modern default of 12.
  const gotRounds = Number(record.params.rounds);
  if (!Number.isInteger(gotRounds) || gotRounds < 4 || gotRounds > BCRYPT_MAX_VERIFY_ROUNDS) {
    return false;
  }
  const mode = options.mode ?? DEFAULTS.mode;
  let pwBytes;
  try {
    pwBytes = normalizePassword(password);
  } catch {
    return false;
  }
  let prepared;
  try {
    prepared = preparePasswordForBcrypt(pwBytes, mode);
  } catch {
    return false;
  }
  const impl = await loadBcrypt();
  try {
    return await impl.compare(isBuffer(prepared) ? prepared.toString('utf8') : prepared, bcryptHash);
  } catch {
    return false;
  }
}

/**
 * @param {string} bcryptHash
 * @param {BcryptRehashCheck} [target]
 * @returns {boolean}
 */
export function needsRehash(bcryptHash, target = {}) {
  const record = parseHash(bcryptHash);
  if (!record || record.algorithm !== 'bcrypt') {
    return true;
  }
  const wantRounds = target.rounds ?? DEFAULTS.rounds;
  const gotRounds = Number(record.params.rounds);
  return gotRounds < wantRounds;
}

function assertRounds(rounds) {
  if (!Number.isInteger(rounds) || rounds < 4 || rounds > 31) {
    throw invalidArgument(
      `bcrypt.options.rounds must be an integer in [4, 31]; got ${rounds}. OWASP 2024 minimum is 10; 12 is a modern default.`,
    );
  }
}
