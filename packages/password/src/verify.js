import { PasswordError, ErrorCode } from './errors.js';
import { parseHash } from './phc.js';
import * as scrypt from './algorithms/scrypt.js';
import * as pbkdf2 from './algorithms/pbkdf2.js';
import * as argon2 from './algorithms/argon2.js';
import * as bcrypt from './algorithms/bcrypt.js';
import { isString } from '@exortek/shared/predicates';

// Static route table — one lookup, no runtime allocations. The bcrypt
// entry accepts an extra option pass-through for `mode`; the others
// ignore extras.
const ROUTES = Object.freeze({
  scrypt: (pw, phc) => scrypt.verify(pw, phc),
  'pbkdf2-sha256': (pw, phc) => pbkdf2.verify(pw, phc),
  'pbkdf2-sha512': (pw, phc) => pbkdf2.verify(pw, phc),
  argon2id: (pw, phc) => argon2.verify(pw, phc),
  argon2i: (pw, phc) => argon2.verify(pw, phc),
  argon2d: (pw, phc) => argon2.verify(pw, phc),
  bcrypt: (pw, phc, opts) => bcrypt.verify(pw, phc, { mode: opts?.bcryptMode }),
});

/**
 * @typedef {object} VerifyOptions
 * @property {import('./algorithms/bcrypt.js').BcryptMode} [bcryptMode]
 *   Forwarded to the bcrypt backend when the stored hash is bcrypt-shaped.
 *   Default `'prehash'` — matches this package's hash-time default.
 */

/**
 * Verify a candidate password against a stored hash of any supported
 * algorithm. The algorithm is auto-detected from the hash's PHC prefix
 * (or the bcrypt `$2b$` shape) — this is the fast path for login
 * handlers that store hashes from multiple algorithms during migration.
 *
 * Returns `false` on any mismatch, including unrecognised or malformed
 * stored values. The only exception raised is `MISSING_PEER_DEP` — if
 * the stored hash's algorithm needs `argon2` or `bcryptjs` and neither
 * is installed, we surface that as an actionable error rather than
 * silently returning `false` (which would look like a wrong password
 * and mask the misconfiguration).
 *
 * @example
 * // Login handler with silent migration
 * const ok = await password.verify(input, user.pwHash)
 * if (!ok) return unauthorized()
 * if (password.needsRehash(user.pwHash)) {
 *   await db.users.update(user.id, { pwHash: await password.scrypt.hash(input) })
 * }
 * return signIn()
 *
 * @param {string | Buffer | Uint8Array} password
 * @param {string} storedHash
 * @param {VerifyOptions} [options]
 * @returns {Promise<boolean>}
 * @throws {PasswordError} With `code: MISSING_PEER_DEP` if the algorithm's
 *                        backend peer is not installed.
 */
export async function verify(password, storedHash, options = {}) {
  if (!isString(storedHash) || storedHash.length === 0) {
    return false;
  }
  const record = parseHash(storedHash);
  if (!record) {
    return false;
  }
  const route = ROUTES[record.algorithm];
  if (!route) {
    return false;
  }
  return route(password, storedHash, options);
}

/**
 * Detect the algorithm behind an arbitrary stored hash. Useful for
 * telemetry ("what fraction of my users still on bcrypt?") and for
 * gating migration behaviour. Returns `null` for values this package
 * doesn't recognise.
 *
 * @param {string} storedHash
 * @returns {import('./phc.js').PasswordAlgorithm | null}
 */
export function identifyAlgorithm(storedHash) {
  const record = parseHash(storedHash);
  return record ? record.algorithm : null;
}

// A canonical decoy hash used by `constantTimeVerify` when the caller
// doesn't have a real stored hash to compare against — see below. Lazily
// minted on first miss so we pay the ~200ms cost once per process, not
// at module load. The password is never a real value; the hash exists
// only so verify has bytes to chew through.
let DECOY_HASH = null;
let decoyPromise = null;
async function ensureDecoy() {
  if (DECOY_HASH) {
    return DECOY_HASH;
  }
  if (!decoyPromise) {
    decoyPromise = scrypt.hash('constant-time-verify-decoy-never-a-real-password', scrypt.scryptDefaults).then(h => {
      DECOY_HASH = h;
      return h;
    });
  }
  return decoyPromise;
}

/**
 * Verify a candidate password against a stored hash *without* leaking
 * whether the account exists via response time. When `storedHash` is
 * falsy (no user, deleted account, tombstoned record) we still run a
 * full verify against a canonical decoy hash — the failed lookup path
 * takes the same wall-clock time as a real wrong-password path.
 *
 * This closes the classic user-enumeration timing attack:
 *
 *   POST /login {email:  existing@…, password: wrong}   → 200ms → 401
 *   POST /login {email:  missing@…,  password: wrong}   → 200ms → 401  ✓
 *
 * Compared to the naive `if (!user) return 401` shortcut, an attacker
 * can no longer walk a wordlist of emails and grade "exists" vs
 * "doesn't exist" by response latency.
 *
 * **Caveat:** the decoy is an scrypt hash at this package's default
 * parameters. If your stored hashes use a different algorithm or much
 * heavier parameters (e.g. tuned argon2id), the decoy path's timing
 * will differ from the real-verify path and a careful attacker can
 * still distinguish them. In that case pre-hash a decoy with YOUR
 * production parameters and call `verify(input, myDecoyHash)` on the
 * missing-user path instead.
 *
 * @example
 * const user = await db.users.findByEmail(input.email)
 * const ok = await password.constantTimeVerify(input.password, user?.pw_hash)
 * if (!ok) return unauthorized()   // same message and timing either way
 *
 * @param {string | Buffer | Uint8Array} input
 * @param {string | null | undefined} storedHash
 * @param {VerifyOptions} [options]
 * @returns {Promise<boolean>}
 */
export async function constantTimeVerify(input, storedHash, options = {}) {
  if (typeof storedHash === 'string' && storedHash.length > 0) {
    return verify(input, storedHash, options);
  }
  // No real hash — run the decoy verify to burn the same time budget.
  // We always return `false` regardless of the decoy's result.
  const decoy = await ensureDecoy();
  await verify(input, decoy, options);
  return false;
}

/**
 * @typedef {object} NeedsRehashOptions
 * @property {'argon2id' | 'scrypt' | 'bcrypt' | 'pbkdf2-sha256' | 'pbkdf2-sha512'} [target='scrypt']
 *   The algorithm you'd rehash *to*. If the stored hash is on a
 *   different algorithm we return `true` — that's the whole point of
 *   this helper in a migration scenario.
 * @property {object} [params]
 *   Target parameters — forwarded to the target algorithm's
 *   `needsRehash`. See the individual algo modules for the shape.
 */

/**
 * Cross-algorithm rehash check. Returns `true` when the stored hash is
 * either (a) on a different algorithm than the target or (b) on the same
 * algorithm but with weaker parameters than the target.
 *
 * The umbrella check defaults to targeting scrypt with this package's
 * OWASP-2024 defaults — matches the zero-dep hot path. If your
 * deployment uses argon2id, pass `{ target: 'argon2id' }`.
 *
 * @param {string} storedHash
 * @param {NeedsRehashOptions} [options]
 * @returns {boolean}
 */
export function needsRehash(storedHash, options = {}) {
  const target = options.target ?? 'scrypt';
  const params = options.params ?? {};
  const record = parseHash(storedHash);
  if (!record) {
    return true;
  }
  if (target === 'scrypt') {
    return scrypt.needsRehash(storedHash, params);
  }
  if (target === 'argon2id' || target === 'argon2i' || target === 'argon2d') {
    return argon2.needsRehash(storedHash, { type: target, ...params });
  }
  if (target === 'bcrypt') {
    return bcrypt.needsRehash(storedHash, params);
  }
  if (target === 'pbkdf2-sha256' || target === 'pbkdf2-sha512') {
    const hashName = target === 'pbkdf2-sha256' ? 'sha256' : 'sha512';
    return pbkdf2.needsRehash(storedHash, { hash: hashName, ...params });
  }
  throw new PasswordError(
    ErrorCode.UNSUPPORTED_ALGORITHM,
    `needsRehash: target must be 'scrypt' | 'argon2id' | 'argon2i' | 'argon2d' | 'bcrypt' | 'pbkdf2-sha256' | 'pbkdf2-sha512'; got '${target}'`,
  );
}
