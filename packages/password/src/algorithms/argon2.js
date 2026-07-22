import { PasswordError, ErrorCode } from '../errors.js';
import { assertPositiveInt } from '../internal/guards.js';
import { normalizePassword } from '../internal/normalize.js';
import { parseHash } from '../phc.js';
import { isString } from '@exortek/shared/predicates';

// OWASP Password Storage Cheat Sheet (2024) Argon2id first-line
// recommendation: m=19 MiB, t=2, p=1. All three parameters are
// independently tunable — see the tuning notes on each field.
//
// Argon2id vs 2i vs 2d:
//   argon2id → hybrid, RECOMMENDED default for password hashing.
//              Resists both side-channel attacks (2i-like early passes)
//              and GPU/ASIC attacks (2d-like later passes).
//   argon2i  → side-channel resistant only. Fine for password hashing
//              but slightly weaker against dedicated hardware.
//   argon2d  → GPU-resistant only. Do NOT use for password hashing —
//              the memory-access pattern leaks bits via side channels.
const DEFAULTS = Object.freeze({
  type: 'argon2id',
  memoryCost: 19 * 1024,
  timeCost: 2,
  parallelism: 1,
  hashLength: 32,
  saltLength: 16,
});

const SUPPORTED_TYPES = new Set(['argon2id', 'argon2i', 'argon2d']);

/**
 * @typedef {'argon2id' | 'argon2i' | 'argon2d'} Argon2Type
 */

/**
 * @typedef {object} Argon2HashOptions
 * @property {Argon2Type} [type='argon2id']
 *   Variant. Default is Argon2id — the hybrid recommended by RFC 9106 and
 *   OWASP. Use `argon2i` only for niche side-channel-only threat models;
 *   never use `argon2d` for password hashing.
 * @property {number} [memoryCost=19456]
 *   Memory cost in KiB. OWASP 2024 default is 19 MiB (19456 KiB). Higher
 *   memory = better GPU/ASIC resistance but slower verify.
 * @property {number} [timeCost=2]
 *   Number of iterations over the memory matrix. 2 is the OWASP default;
 *   raise to 3-4 for high-security environments (KMS-style).
 * @property {number} [parallelism=1]
 *   Lanes / threads. 1 is safest — parallelism > 1 has open questions
 *   around timing behaviour under contention.
 * @property {number} [hashLength=32]
 *   Output length in bytes.
 * @property {number} [saltLength=16]
 *   Random salt length. Argon2 recommends ≥ 16 bytes.
 * @property {Buffer} [salt]
 *   Pre-generated salt (KAT vectors only).
 */

/**
 * @typedef {object} Argon2RehashCheck
 * @property {Argon2Type} [type]
 * @property {number} [memoryCost]
 * @property {number} [timeCost]
 * @property {number} [parallelism]
 * @property {number} [hashLength]
 * @property {number} [version]         Argon2 version — 0x13 (19) is current.
 */

/** Immutable defaults for {@link needsRehash} and preset consumers. */
export const argon2Defaults = DEFAULTS;

// Dynamic import so the peer never runs at module-load time — importing
// `@exortek/password` or `@exortek/password/scrypt` works without argon2
// installed.
//
// We resolve the peer once and cache the outcome — `impl` on success,
// `probed=true` with `impl=null` on failure. Every subsequent
// `hash`/`verify` becomes a synchronous property read + a thrown error
// (rather than another try/catch through `await import`) when the peer
// is missing.
let impl = null;
let probed = false;

async function loadArgon2() {
  if (probed) {
    if (impl) {
      return impl;
    }
    throw missingPeerError();
  }
  try {
    const mod = await import('argon2');
    // The `argon2` npm package exposes its API on `.default` under
    // CJS-ESM interop; unwrap so callers see a uniform shape.
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
    "@exortek/password's argon2 backend requires the 'argon2' npm package. Install it as a peer:\n\n  yarn add argon2\n\nOr, if node-gyp is not an option for your deploy target, use the scrypt backend instead:\n\n  import { scrypt } from '@exortek/password/scrypt'\n",
    cause ? { cause } : undefined,
  );
}

function typeToArgon2Enum(impl, type) {
  const argon2Enum = impl.argon2id !== undefined ? impl : impl.default;
  const map = {
    argon2id: argon2Enum.argon2id,
    argon2i: argon2Enum.argon2i,
    argon2d: argon2Enum.argon2d,
  };
  return map[type];
}

/**
 * Hash a password with Argon2 via the `argon2` npm package. Requires the
 * peer dependency to be installed; throws {@link PasswordError} with
 * `code: MISSING_PEER_DEP` and an actionable message if not.
 *
 * The output is the PHC string emitted by the library — starts with
 * `$argon2id$v=19$m=...$t=...$p=...$<salt>$<hash>`.
 *
 * @param {string | Buffer | Uint8Array} password
 * @param {Argon2HashOptions} [options]
 * @returns {Promise<string>}
 */
export async function hash(password, options = {}) {
  const type = options.type ?? DEFAULTS.type;
  assertType(type);
  const memoryCost = options.memoryCost ?? DEFAULTS.memoryCost;
  const timeCost = options.timeCost ?? DEFAULTS.timeCost;
  const parallelism = options.parallelism ?? DEFAULTS.parallelism;
  const hashLength = options.hashLength ?? DEFAULTS.hashLength;
  const saltLength = options.saltLength ?? DEFAULTS.saltLength;
  assertPositiveInt(memoryCost, 'argon2.options.memoryCost');
  assertPositiveInt(timeCost, 'argon2.options.timeCost');
  assertPositiveInt(parallelism, 'argon2.options.parallelism');
  assertPositiveInt(hashLength, 'argon2.options.hashLength');
  assertPositiveInt(saltLength, 'argon2.options.saltLength');

  const pwBytes = normalizePassword(password);
  const impl = await loadArgon2();

  const argonOptions = {
    type: typeToArgon2Enum(impl, type),
    memoryCost,
    timeCost,
    parallelism,
    hashLength,
    saltLength,
  };
  if (options.salt) {
    argonOptions.salt = Buffer.from(options.salt);
  }

  return impl.hash(pwBytes, argonOptions);
}

/**
 * Verify a candidate password against an Argon2 PHC hash. Returns `false`
 * on any mismatch — including malformed hashes and wrong algorithms —
 * so callers can feed arbitrary stored values safely.
 *
 * @param {string | Buffer | Uint8Array} password
 * @param {string} phcHash
 * @returns {Promise<boolean>}
 */
export async function verify(password, phcHash) {
  if (!isString(phcHash) || !phcHash.startsWith('$argon2')) {
    return false;
  }
  const impl = await loadArgon2();
  let pwBytes;
  try {
    pwBytes = normalizePassword(password);
  } catch {
    return false;
  }
  try {
    return await impl.verify(phcHash, pwBytes);
  } catch {
    // The `argon2` package throws on malformed input rather than
    // returning false — normalise into a boolean here so the caller
    // never sees an exception from a wrong-shape stored value.
    return false;
  }
}

/**
 * Report whether a stored Argon2 hash's parameters are weaker than the
 * target. If the type differs (e.g. stored `argon2i`, target `argon2id`)
 * this returns `true` so the user gets rehashed onto the recommended
 * variant on their next successful login.
 *
 * @param {string} phcHash
 * @param {Argon2RehashCheck} [target]
 * @returns {boolean}
 */
export function needsRehash(phcHash, target = {}) {
  const record = parseHash(phcHash);
  if (!record || !record.algorithm.startsWith('argon2')) {
    return true;
  }
  const wantType = target.type ?? DEFAULTS.type;
  if (record.algorithm !== wantType) {
    return true;
  }
  const wantMemory = target.memoryCost ?? DEFAULTS.memoryCost;
  const wantTime = target.timeCost ?? DEFAULTS.timeCost;
  const wantParallelism = target.parallelism ?? DEFAULTS.parallelism;
  const wantHashLength = target.hashLength ?? DEFAULTS.hashLength;
  const wantVersion = target.version ?? 0x13;
  const gotMemory = Number(record.params.m);
  const gotTime = Number(record.params.t);
  const gotParallelism = Number(record.params.p);
  const gotVersion = Number(record.params.v);
  const gotHashLength = record.hash ? record.hash.length : 0;
  return (
    gotMemory < wantMemory ||
    gotTime < wantTime ||
    gotParallelism < wantParallelism ||
    gotHashLength < wantHashLength ||
    gotVersion < wantVersion
  );
}

function assertType(type) {
  if (!SUPPORTED_TYPES.has(type)) {
    throw new PasswordError(
      ErrorCode.UNSUPPORTED_ALGORITHM,
      `argon2: type must be one of ${[...SUPPORTED_TYPES].join(', ')}; got '${type}'. Prefer 'argon2id' for password hashing.`,
    );
  }
}
