import { PasswordError, ErrorCode } from './errors.js';
import { b64Encode, b64Decode } from './internal/base64.js';
import { assertObject, invalidArgument } from './internal/guards.js';

/**
 * @typedef {'argon2i' | 'argon2d' | 'argon2id' | 'scrypt' | 'pbkdf2-sha256' | 'pbkdf2-sha512' | 'bcrypt'} PasswordAlgorithm
 */

/**
 * @typedef {object} ParsedHash
 * @property {PasswordAlgorithm} algorithm
 * @property {Record<string, string | number>} params
 *   Algorithm-specific tuning knobs, already numeric-typed where sensible
 *   (e.g. Argon2 `m`, `t`, `p` are numbers; scrypt `ln`/`r`/`p` are numbers;
 *   pbkdf2 iteration count is a number; bcrypt `rounds` is a number).
 * @property {Buffer | null} salt
 *   `null` only for legacy bcrypt strings — the bcrypt format packs salt
 *   and hash together in a single field; use {@link ParsedHash.raw} to
 *   feed the full record back into the bcrypt library.
 * @property {Buffer | null} hash
 *   `null` for bcrypt (same reason).
 * @property {string} raw
 *   The original string, unmodified. Pass this back into the algo's
 *   `verify` when you're just routing.
 */

// The PHC string spec (https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md):
//
//   $<id>$[<param>=<value>(,<param>=<value>)*]$<salt>$<hash>
//
// Argon2 adds a version segment: $argon2id$v=19$m=...$<salt>$<hash>.
// Everything is unpadded base64 (RFC 7468); the salt and hash MAY be
// empty (rare — we treat empty hash as a malformed record).

const KNOWN_ALGORITHMS = new Set(['argon2i', 'argon2d', 'argon2id', 'scrypt', 'pbkdf2-sha256', 'pbkdf2-sha512']);

// bcrypt's non-PHC format: $2<variant>$<rounds>$<22-char-salt><31-char-hash>
// Variant letters: 2, 2a, 2b, 2x, 2y. Modern implementations emit 2b.
const BCRYPT_RE = /^\$2[abxy]?\$(\d{2})\$([./A-Za-z0-9]{53})$/;

/**
 * Parse any hash string this package understands into a structured
 * record. Never throws for a string the caller hands over — returns
 * `null` for unrecognised or malformed input so callers can treat "not
 * one of ours" as a plain routing decision.
 *
 * @param {unknown} input
 * @returns {ParsedHash | null}
 */
export function parseHash(input) {
  if (typeof input !== 'string' || input.length === 0) {
    return null;
  }
  const bcryptMatch = BCRYPT_RE.exec(input);
  if (bcryptMatch) {
    const rounds = Number.parseInt(bcryptMatch[1], 10);
    if (!Number.isFinite(rounds) || rounds < 4 || rounds > 31) {
      return null;
    }
    return {
      algorithm: 'bcrypt',
      params: { rounds },
      salt: null,
      hash: null,
      raw: input,
    };
  }
  if (input[0] !== '$') {
    return null;
  }
  const parts = input.split('$');
  // Leading '$' produces an empty first segment. Valid PHC:
  //   ['', id, params?, salt, hash]  → length 4 or 5
  // Argon2 adds v=19 as its own field:
  //   ['', 'argon2id', 'v=19', 'm=...,t=...,p=...', salt, hash]  → length 6
  if (parts.length < 4 || parts.length > 6) {
    return null;
  }
  const [, id, ...rest] = parts;
  if (!KNOWN_ALGORITHMS.has(id)) {
    return null;
  }
  const hash = rest.pop();
  const salt = rest.pop();
  if (!salt || !hash) {
    return null;
  }
  const params = {};
  for (const segment of rest) {
    if (segment.length === 0) {
      continue;
    }
    for (const kv of segment.split(',')) {
      const eq = kv.indexOf('=');
      if (eq <= 0) {
        return null;
      }
      const k = kv.slice(0, eq);
      const v = kv.slice(eq + 1);
      params[k] = /^\d+$/.test(v) ? Number.parseInt(v, 10) : v;
    }
  }
  let saltBytes;
  let hashBytes;
  try {
    saltBytes = b64Decode(salt);
    hashBytes = b64Decode(hash);
  } catch {
    return null;
  }
  if (hashBytes.length === 0) {
    return null;
  }
  return {
    algorithm: /** @type {PasswordAlgorithm} */ (id),
    params,
    salt: saltBytes,
    hash: hashBytes,
    raw: input,
  };
}

/**
 * Serialise a PHC record. Argon2 gets the version segment prepended
 * automatically when a `v` param is present. Bcrypt strings can NOT be
 * serialised through this helper — they follow their own format and
 * come out of the bcrypt library pre-formatted.
 *
 * @param {{
 *   algorithm: Exclude<PasswordAlgorithm, 'bcrypt'>,
 *   params: Record<string, string | number>,
 *   salt: Buffer | Uint8Array,
 *   hash: Buffer | Uint8Array,
 * }} record
 * @returns {string}
 */
export function serialiseHash(record) {
  assertObject(record, 'serialiseHash.record');
  if (record.algorithm === 'bcrypt') {
    throw invalidArgument(
      'serialiseHash.record.algorithm: bcrypt uses a non-PHC format — take the string the bcrypt library returned directly',
    );
  }
  if (!KNOWN_ALGORITHMS.has(record.algorithm)) {
    throw new PasswordError(ErrorCode.UNSUPPORTED_ALGORITHM, `serialiseHash: unknown algorithm '${record.algorithm}'`);
  }
  const params = record.params ?? {};
  const version = params.v;
  const paramEntries = Object.entries(params).filter(([k]) => k !== 'v');
  const paramSegment = paramEntries.map(([k, v]) => `${k}=${v}`).join(',');
  const salt = b64Encode(record.salt);
  const hash = b64Encode(record.hash);
  if (version !== undefined) {
    return `$${record.algorithm}$v=${version}$${paramSegment}$${salt}$${hash}`;
  }
  return `$${record.algorithm}$${paramSegment}$${salt}$${hash}`;
}
