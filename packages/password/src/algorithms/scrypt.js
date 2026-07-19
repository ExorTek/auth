import { randomBytes, scrypt as scryptCb, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import { assertPositiveInt, invalidArgument } from '../internal/guards.js';
import { normalizePassword } from '../internal/normalize.js';
import { parseHash, serialiseHash } from '../phc.js';

const scryptAsync = promisify(scryptCb);

// OWASP Password Storage Cheat Sheet (2024): scrypt with N=2^17, r=8, p=1.
// N is the CPU/memory cost — 2^17 = 131,072 iterations. The
// corresponding memory footprint is ~128 MiB × p bytes; be aware of this
// on tiny containers.
const DEFAULTS = Object.freeze({
  N: 1 << 17,
  r: 8,
  p: 1,
  keyLength: 32,
  saltLength: 16,
});

// scrypt PHC parameters: $scrypt$ln=<log2N>,r=<r>,p=<p>$<salt>$<hash>
// The `ln` field is log2 of N — canonical way to express the cost so it
// fits into a single small integer.

/**
 * @typedef {object} ScryptHashOptions
 * @property {number} [N=131072]        CPU / memory cost — must be a power of two.
 * @property {number} [r=8]             Block size — RFC 7914 fixes this at 8 for
 *                                       memory-hardness; do not change without a reason.
 * @property {number} [p=1]             Parallelism.
 * @property {number} [keyLength=32]    Output length in bytes. 32 covers a full
 *                                       256-bit derived key.
 * @property {number} [saltLength=16]   Random salt length in bytes. 16 bytes = 128 bits;
 *                                       the RFC 7914 recommended minimum.
 * @property {Buffer} [salt]            Pre-generated salt. Almost always omitted —
 *                                       pass one only for reproducible tests / KAT vectors.
 * @property {number} [maxmem]          Optional cap on peak memory in bytes. When
 *                                       omitted Node scales it to `128 * N * r + 32MB`.
 */

/**
 * @typedef {object} ScryptVerifyOptions
 * @property {number} [maxmem]          Same as {@link ScryptHashOptions.maxmem}.
 */

/**
 * @typedef {object} ScryptRehashCheck
 * @property {number} [N]               Target CPU cost.
 * @property {number} [r]               Target block size.
 * @property {number} [p]               Target parallelism.
 * @property {number} [keyLength]       Target derived-key length.
 */

/**
 * Immutable defaults used when the caller omits {@link ScryptHashOptions}
 * fields. Exposed so `presets.js` and `needsRehash` can compare against
 * the current recommendation without duplicating constants.
 */
export const scryptDefaults = DEFAULTS;

/**
 * Hash a password with scrypt (RFC 7914) using OWASP-2024 defaults. Emits
 * a self-describing PHC string that {@link verify} can consume without
 * being told which algorithm was used.
 *
 *   $scrypt$ln=17,r=8,p=1$<b64-salt>$<b64-hash>
 *
 * @param {string | Buffer | Uint8Array} password
 * @param {ScryptHashOptions} [options]
 * @returns {Promise<string>}   PHC-formatted hash.
 */
export async function hash(password, options = {}) {
  const N = options.N ?? DEFAULTS.N;
  const r = options.r ?? DEFAULTS.r;
  const p = options.p ?? DEFAULTS.p;
  const keyLength = options.keyLength ?? DEFAULTS.keyLength;
  const saltLength = options.saltLength ?? DEFAULTS.saltLength;
  assertN(N);
  assertPositiveInt(r, 'scrypt.options.r');
  assertPositiveInt(p, 'scrypt.options.p');
  assertPositiveInt(keyLength, 'scrypt.options.keyLength');
  assertPositiveInt(saltLength, 'scrypt.options.saltLength');

  const pwBytes = normalizePassword(password);
  const salt = options.salt ?? randomBytes(saltLength);
  const derived = await scryptAsync(pwBytes, salt, keyLength, {
    N,
    r,
    p,
    maxmem: options.maxmem ?? autoMaxmem(N, r),
  });
  return serialiseHash({
    algorithm: 'scrypt',
    params: { ln: Math.log2(N), r, p },
    salt,
    hash: derived,
  });
}

/**
 * Verify a candidate password against a scrypt PHC hash in constant
 * time. Returns `false` on any mismatch — including malformed hashes
 * and wrong algorithms — so callers can safely feed arbitrary stored
 * values without a try/catch.
 *
 * @param {string | Buffer | Uint8Array} password
 * @param {string} phcHash        The scrypt PHC string returned by {@link hash}.
 * @param {ScryptVerifyOptions} [options]
 * @returns {Promise<boolean>}
 */
export async function verify(password, phcHash, options = {}) {
  const record = parseHash(phcHash);
  if (!record || record.algorithm !== 'scrypt' || !record.salt || !record.hash) {
    return false;
  }
  const ln = Number(record.params.ln);
  const r = Number(record.params.r);
  const p = Number(record.params.p);
  if (!Number.isInteger(ln) || ln < 1 || ln > 31) {
    return false;
  }
  if (!Number.isInteger(r) || r < 1 || !Number.isInteger(p) || p < 1) {
    return false;
  }
  const N = 1 << ln;
  let pwBytes;
  try {
    pwBytes = normalizePassword(password);
  } catch {
    return false;
  }
  const derived = await scryptAsync(pwBytes, record.salt, record.hash.length, {
    N,
    r,
    p,
    maxmem: options.maxmem ?? autoMaxmem(N, r),
  });
  return derived.length === record.hash.length && timingSafeEqual(derived, record.hash);
}

/**
 * Report whether a stored scrypt hash's parameters are weaker than the
 * target — a signal to rehash on the next successful login.
 *
 *   if (await scrypt.verify(pw, stored)) {
 *     if (scrypt.needsRehash(stored)) {
 *       await db.users.update(id, { pw_hash: await scrypt.hash(pw) })
 *     }
 *   }
 *
 * @param {string} phcHash
 * @param {ScryptRehashCheck} [target]
 * @returns {boolean}
 */
export function needsRehash(phcHash, target = {}) {
  const record = parseHash(phcHash);
  if (!record || record.algorithm !== 'scrypt') {
    return true;
  }
  const wantN = target.N ?? DEFAULTS.N;
  const wantR = target.r ?? DEFAULTS.r;
  const wantP = target.p ?? DEFAULTS.p;
  const wantKeyLength = target.keyLength ?? DEFAULTS.keyLength;
  const gotN = 1 << Number(record.params.ln);
  const gotR = Number(record.params.r);
  const gotP = Number(record.params.p);
  const gotKeyLength = record.hash ? record.hash.length : 0;
  return gotN < wantN || gotR < wantR || gotP < wantP || gotKeyLength < wantKeyLength;
}

function assertN(N) {
  if (!Number.isInteger(N) || N < 2 || (N & (N - 1)) !== 0) {
    throw invalidArgument(
      `scrypt.options.N must be a power of two ≥ 2; got ${N}. Typical values: 2^15 (32768) for interactive, 2^17 (131072) for OWASP-2024 default, 2^20 (1048576) for sensitive keys.`,
    );
  }
  if (N > 1 << 24) {
    throw invalidArgument(
      `scrypt.options.N=${N} would require multi-gigabyte allocations. If you truly need this, raise the maxmem option and revisit whether a hash is the right primitive here.`,
    );
  }
}

function autoMaxmem(N, r) {
  // Node's default maxmem is 32MB, which explodes as soon as N crosses
  // 2^15. Scale it against the parameters — 128 × N × r is the working-set
  // formula from RFC 7914 §5, plus a 16 MB slack for scrypt's own
  // scratch space.
  return 128 * N * r + 16 * 1024 * 1024;
}
