import crypto from 'node:crypto';
import { CryptoError, ErrorCode } from '../errors.js';
import { assertBytesOrString, assertOptionalObject, invalidArgument } from '../internal/guards.js';
import { hkdf } from '../hash/hkdf.js';
import { toBuffer } from '../internal/bytes.js';

const VERSION = 0x01;
const IV_LEN = 12;
const EXP_LEN = 8;
const TAG_LEN = 16;
const HEADER_LEN = 1 + IV_LEN + EXP_LEN;
const HKDF_INFO = Buffer.from('exortek-crypto-seal-v1', 'utf8');

const DURATION_UNITS = { ms: 1, s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000, w: 604_800_000 };
const DURATION_RE = /^(\d+)(ms|s|m|h|d|w)$/;

/**
 * @typedef {object} SealOptions
 * @property {number | string} ttl
 *   Time-to-live. Either a positive number of seconds, or a duration string
 *   with a unit suffix: `ms`, `s`, `m`, `h`, `d`, `w`. Examples: `900`,
 *   `'15m'`, `'1h'`, `'30d'`.
 * @property {number} [now=Date.now()]
 *   Injectable clock for tests. Milliseconds since Unix epoch.
 */

/**
 * @typedef {object} UnsealOptions
 * @property {number} [now=Date.now()]
 *   Injectable clock for tests. Milliseconds since Unix epoch.
 * @property {number} [clockSkew=0]
 *   Allowed clock skew in seconds — permits tokens up to this many seconds
 *   past their nominal expiry.
 */

/**
 * @typedef {object} SealResult
 * @property {any}    payload      The deserialised payload.
 * @property {number} expiresAt    Millisecond Unix timestamp.
 */

/**
 * Encrypt and time-stamp an arbitrary JSON-serialisable payload into a short
 * opaque token, suitable for password-reset links, email-verification codes,
 * magic-link tokens, or any single-use ticket that needs to expire on its own.
 *
 * The token is authenticated (AES-256-GCM) — tampering flips it to invalid on
 * {@link unseal}. The expiry is part of the authenticated data, so an
 * attacker can't extend a token by editing bytes. The encryption key is
 * derived from `secret` via HKDF-SHA-256; the same `secret` will always
 * derive the same key.
 *
 * **When to reach for {@link seal} vs. a JWT:** JWT is a signed, publicly
 * inspectable envelope built to a JOSE standard, meant for stateless auth
 * between services. `seal` is an *encrypted* opaque token — smaller, no
 * standard to argue about, payload is private. Reach for it when the payload
 * ("reset user 42's password", "confirm this email") is not something the
 * bearer should read, and the token doesn't have to interoperate with anyone
 * else.
 *
 * @param {any}                          payload   Any JSON-serialisable value.
 * @param {string | Buffer | Uint8Array} secret    Key material. Anything with
 *                                                  ≥ 16 bytes of entropy is fine;
 *                                                  short passphrases weaken it.
 * @param {SealOptions}                  options
 * @returns {string}                                base64url token.
 * @throws {CryptoError}   With code:
 *   - `INVALID_ARGUMENT` if `payload` is not JSON-serialisable, `secret` /
 *     `options.ttl` are invalid, or the derived expiry overflows the token's
 *     8-byte timestamp field
 *
 * @example
 * // Password-reset link — 1-hour ticket
 * const token = seal({ userId: 42, purpose: 'pw-reset' }, RESET_SECRET, { ttl: '1h' })
 * res.redirect(`/reset?t=${token}`)
 *
 * @example
 * // Email verification — 24 hours
 * const token = seal({ email }, VERIFY_SECRET, { ttl: '24h' })
 */
export function seal(payload, secret, options) {
  assertBytesOrString(secret, 'secret');
  assertOptionalObject(options, 'options');
  if (options === undefined || options.ttl === undefined) {
    throw invalidArgument(
      "options.ttl is required — pass either a positive integer of seconds or a duration string like '1h' / '15m' / '7d'",
    );
  }
  const ttlMs = _parseTtl(options.ttl);
  const now = options.now ?? Date.now();
  if (!Number.isFinite(now) || now < 0) {
    throw invalidArgument(`options.now must be a non-negative finite number (ms since epoch); got ${_describe(now)}`);
  }
  const expiresAt = now + ttlMs;
  if (!Number.isSafeInteger(expiresAt)) {
    throw invalidArgument(
      `expiry (now + ttl) exceeds Number.MAX_SAFE_INTEGER — pick a shorter ttl or a smaller now (got ${now} + ${ttlMs})`,
    );
  }
  const plaintext = _serialise(payload);
  const key = _deriveKey(secret);
  const iv = crypto.randomBytes(IV_LEN);
  const header = Buffer.alloc(HEADER_LEN);
  header[0] = VERSION;
  iv.copy(header, 1);
  header.writeBigUInt64BE(BigInt(expiresAt), 1 + IV_LEN);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(header);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([header, ciphertext, tag]).toString('base64url');
}

/**
 * Verify and open a token produced by {@link seal}.
 *
 * Throws with a stable {@link ErrorCode} so callers can distinguish the three
 * failure modes for UX purposes:
 *
 *   - `TOKEN_MALFORMED` — the token bytes are truncated or use an unknown
 *     version. Almost always means the input never was a valid token.
 *   - `TOKEN_TAMPERED` — GCM authentication failed. Wrong secret, or the
 *     bytes were edited. Do not distinguish these to the user.
 *   - `TOKEN_EXPIRED` — token was valid but its TTL has passed. Ask the user
 *     to request a fresh one ("this link has expired").
 *
 * **Secret rotation.** `secret` may be a single key or an array `[newest, …older]`.
 * Each is tried in order; the first that authenticates wins. Rotate by (a) issuing
 * new tokens with a fresh secret, (b) unsealing with `[fresh, previous]` until the
 * previous secret's TTL horizon has passed, then (c) dropping the old entry. Cost
 * is one HKDF + one AES-GCM per unmatched secret — cheap for 2–3 keys.
 *
 * @param {string}                                                           token   `base64url` from {@link seal}.
 * @param {string | Buffer | Uint8Array | Array<string | Buffer | Uint8Array>} secret  Key material, or an array of keys for rotation.
 * @param {UnsealOptions}                                                    [options]
 * @returns {SealResult}
 * @throws {CryptoError}
 *
 * @example
 * try {
 *   const { payload } = unseal(req.query.t, RESET_SECRET)
 *   await resetPassword(payload.userId)
 * } catch (err) {
 *   if (err.code === ErrorCode.TOKEN_EXPIRED)   return renderExpiredPage()
 *   if (err.code === ErrorCode.TOKEN_TAMPERED)  return render404()
 *   throw err
 * }
 *
 * @example
 * // Rotate SEAL_SECRET without invalidating in-flight tokens:
 * const { payload } = unseal(token, [SEAL_SECRET_NEW, SEAL_SECRET_OLD], { clockSkew: 5 })
 */
export function unseal(token, secret, options) {
  if (typeof token !== 'string') {
    throw new CryptoError(
      ErrorCode.TOKEN_MALFORMED,
      `token must be a string (base64url from seal()); got ${_describe(token)}`,
    );
  }
  const secrets = Array.isArray(secret) ? secret : [secret];
  if (secrets.length === 0) {
    throw invalidArgument('secret list is empty — pass at least one key (or an array of keys for rotation)');
  }
  for (const s of secrets) {
    assertBytesOrString(s, 'secret');
  }
  assertOptionalObject(options, 'options');
  const bytes = Buffer.from(token, 'base64url');
  if (bytes.length < HEADER_LEN + TAG_LEN) {
    throw new CryptoError(
      ErrorCode.TOKEN_MALFORMED,
      `token is truncated — need at least ${HEADER_LEN + TAG_LEN} bytes after base64url decode, got ${bytes.length}. Ensure the value was not clipped by URL length limits or logging redaction.`,
    );
  }
  if (bytes[0] !== VERSION) {
    throw new CryptoError(
      ErrorCode.TOKEN_MALFORMED,
      `unknown token version 0x${bytes[0].toString(16)} (this library emits 0x${VERSION.toString(16).padStart(2, '0')}). The token was probably not produced by @exortek/crypto.`,
    );
  }
  const iv = bytes.subarray(1, 1 + IV_LEN);
  const expiresAt = Number(bytes.readBigUInt64BE(1 + IV_LEN));
  const header = bytes.subarray(0, HEADER_LEN);
  const tag = bytes.subarray(bytes.length - TAG_LEN);
  const ciphertext = bytes.subarray(HEADER_LEN, bytes.length - TAG_LEN);

  let plaintext = null;
  let lastCause;
  for (const s of secrets) {
    const key = _deriveKey(s);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAAD(header);
    decipher.setAuthTag(tag);
    try {
      plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      break;
    } catch (cause) {
      lastCause = cause;
    }
  }
  if (plaintext === null) {
    throw new CryptoError(
      ErrorCode.TOKEN_TAMPERED,
      `token authentication failed against ${secrets.length === 1 ? 'the provided secret' : `all ${secrets.length} provided secrets`} — wrong secret, tampered bytes, or a token issued with a rotated secret. Never render this hint to end users; treat it as unauthenticated.`,
      { cause: lastCause },
    );
  }

  // Expiry is inside the AAD, so we only trust it after auth succeeds.
  const now = options?.now ?? Date.now();
  const skewMs = (options?.clockSkew ?? 0) * 1000;
  if (now > expiresAt + skewMs) {
    const overdueSec = Math.round((now - expiresAt) / 1000);
    throw new CryptoError(
      ErrorCode.TOKEN_EXPIRED,
      `token expired ${overdueSec}s ago (expiresAt=${new Date(expiresAt).toISOString()}, now=${new Date(now).toISOString()}). Ask the user to request a fresh one.`,
      { cause: { expiresAt, now } },
    );
  }

  let payload;
  try {
    payload = JSON.parse(plaintext.toString('utf8'));
  } catch (cause) {
    throw new CryptoError(
      ErrorCode.TOKEN_MALFORMED,
      'token payload is not valid JSON — the token authenticated correctly but its plaintext could not be parsed. This indicates a producer / consumer version mismatch.',
      { cause },
    );
  }
  return { payload, expiresAt };
}

function _serialise(payload) {
  let s;
  try {
    s = JSON.stringify(payload);
  } catch (cause) {
    // Keep the CryptoError shape — this branch carries a cause chain
    // and the bound `invalidArgument` doesn't (yet) surface `{ cause }`.
    throw new CryptoError(
      ErrorCode.INVALID_ARGUMENT,
      'payload is not JSON-serialisable — remove BigInt, cyclic references, or non-plain objects before sealing',
      { cause },
    );
  }
  if (s === undefined) {
    throw invalidArgument(
      'payload serialises to undefined — the root value is undefined, a function, or a symbol. Wrap it in an object: seal({ value: yourPayload }, secret, { ttl })',
    );
  }
  return Buffer.from(s, 'utf8');
}

/**
 * @private — cheap describe helper for arguments in error messages.
 */
function _describe(v) {
  if (v === null || v === undefined) {
    return String(v);
  }
  if (typeof v === 'string') {
    return `a string of length ${v.length}`;
  }
  if (typeof v === 'number' || typeof v === 'boolean') {
    return `${typeof v} ${v}`;
  }
  if (Buffer.isBuffer(v)) {
    return `Buffer of length ${v.length}`;
  }
  if (v instanceof Uint8Array) {
    return `Uint8Array of length ${v.length}`;
  }
  return typeof v === 'object' ? (v.constructor?.name ?? 'object') : typeof v;
}

// HKDF result cache. seal/unseal run on the hot path (every session
// verify), and the secret → key derivation is fully deterministic, so
// re-deriving per call is pure waste. Only STRING secrets are cached:
// strings are immutable, whereas a Buffer's contents can be mutated
// (e.g. zeroized) after the fact, which would make an identity-keyed
// cache silently serve a key for material that no longer exists.
const KEY_CACHE_MAX = 8;
/** @type {Map<string, Buffer>} */
const _keyCache = new Map();

function _deriveKey(secret) {
  const cacheable = typeof secret === 'string';
  if (cacheable) {
    const hit = _keyCache.get(secret);
    if (hit) {
      return hit;
    }
  }
  const key = hkdf(toBuffer(secret, 'secret'), {
    salt: Buffer.of(VERSION),
    info: HKDF_INFO,
    length: 32,
    hash: 'sha256',
  });
  if (cacheable) {
    if (_keyCache.size >= KEY_CACHE_MAX) {
      // Drop the oldest entry — realistic deployments hold 1-3 secrets
      // (current + rotation tail), so eviction is a safety valve, not a
      // steady-state path.
      _keyCache.delete(_keyCache.keys().next().value);
    }
    _keyCache.set(secret, key);
  }
  return key;
}

function _parseTtl(ttl) {
  if (typeof ttl === 'number') {
    if (!Number.isFinite(ttl) || ttl <= 0 || !Number.isSafeInteger(ttl)) {
      throw invalidArgument(
        `options.ttl (number) must be a positive integer of seconds; got ${ttl}. For sub-second granularity use a duration string like '500ms'.`,
      );
    }
    return ttl * 1000;
  }
  if (typeof ttl === 'string') {
    const m = DURATION_RE.exec(ttl);
    if (!m) {
      throw invalidArgument(
        `options.ttl string ${JSON.stringify(ttl)} does not parse — use '<number><ms|s|m|h|d|w>' (e.g. '500ms', '15m', '1h', '24h', '7d', '2w'). No spaces, no fractional numbers, unit is required.`,
      );
    }
    const n = Number(m[1]);
    if (n <= 0) {
      throw invalidArgument(`options.ttl duration must be positive; got ${ttl}`);
    }
    return n * DURATION_UNITS[m[2]];
  }
  throw invalidArgument(
    `options.ttl must be a positive number of seconds or a duration string ('1h', '24h', '7d'); got ${_describe(ttl)}`,
  );
}
