import crypto from 'node:crypto';
import { CryptoError, ErrorCode } from '../errors.js';
import { assertBytesOrString, assertOptionalObject } from '../internal/validate.js';
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
    throw new CryptoError(ErrorCode.INVALID_ARGUMENT, 'options.ttl is required');
  }
  const ttlMs = _parseTtl(options.ttl);
  const now = options.now ?? Date.now();
  if (!Number.isFinite(now) || now < 0) {
    throw new CryptoError(ErrorCode.INVALID_ARGUMENT, 'options.now must be a non-negative finite number');
  }
  const expiresAt = now + ttlMs;
  if (!Number.isSafeInteger(expiresAt)) {
    throw new CryptoError(ErrorCode.INVALID_ARGUMENT, 'expiry timestamp is not a safe integer');
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
 * @param {string}                       token   `base64url` from {@link seal}.
 * @param {string | Buffer | Uint8Array} secret  Same key material as sealing.
 * @param {UnsealOptions}                [options]
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
 */
export function unseal(token, secret, options) {
  if (typeof token !== 'string') {
    throw new CryptoError(ErrorCode.TOKEN_MALFORMED, 'token must be a string');
  }
  assertBytesOrString(secret, 'secret');
  assertOptionalObject(options, 'options');
  const bytes = Buffer.from(token, 'base64url');
  if (bytes.length < HEADER_LEN + TAG_LEN) {
    throw new CryptoError(ErrorCode.TOKEN_MALFORMED, 'token is truncated');
  }
  if (bytes[0] !== VERSION) {
    throw new CryptoError(ErrorCode.TOKEN_MALFORMED, `unknown token version 0x${bytes[0].toString(16)}`);
  }
  const iv = bytes.subarray(1, 1 + IV_LEN);
  const expiresAt = Number(bytes.readBigUInt64BE(1 + IV_LEN));
  const header = bytes.subarray(0, HEADER_LEN);
  const tag = bytes.subarray(bytes.length - TAG_LEN);
  const ciphertext = bytes.subarray(HEADER_LEN, bytes.length - TAG_LEN);

  const key = _deriveKey(secret);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAAD(header);
  decipher.setAuthTag(tag);
  let plaintext;
  try {
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (cause) {
    throw new CryptoError(ErrorCode.TOKEN_TAMPERED, 'token authentication failed', { cause });
  }

  // Expiry is inside the AAD, so we only trust it after auth succeeds.
  const now = options?.now ?? Date.now();
  const skewMs = (options?.clockSkew ?? 0) * 1000;
  if (now > expiresAt + skewMs) {
    throw new CryptoError(ErrorCode.TOKEN_EXPIRED, 'token expired', { cause: { expiresAt, now } });
  }

  let payload;
  try {
    payload = JSON.parse(plaintext.toString('utf8'));
  } catch (cause) {
    throw new CryptoError(ErrorCode.TOKEN_MALFORMED, 'token payload is not valid JSON', { cause });
  }
  return { payload, expiresAt };
}

function _serialise(payload) {
  let s;
  try {
    s = JSON.stringify(payload);
  } catch (cause) {
    throw new CryptoError(ErrorCode.INVALID_ARGUMENT, 'payload is not JSON-serialisable', { cause });
  }
  if (s === undefined) {
    throw new CryptoError(ErrorCode.INVALID_ARGUMENT, 'payload serialises to undefined (function / symbol at root)');
  }
  return Buffer.from(s, 'utf8');
}

function _deriveKey(secret) {
  return hkdf(toBuffer(secret, 'secret'), {
    salt: Buffer.of(VERSION),
    info: HKDF_INFO,
    length: 32,
    hash: 'sha256',
  });
}

function _parseTtl(ttl) {
  if (typeof ttl === 'number') {
    if (!Number.isFinite(ttl) || ttl <= 0 || !Number.isSafeInteger(ttl)) {
      throw new CryptoError(ErrorCode.INVALID_ARGUMENT, 'options.ttl (number) must be a positive integer of seconds');
    }
    return ttl * 1000;
  }
  if (typeof ttl === 'string') {
    const m = DURATION_RE.exec(ttl);
    if (!m) {
      throw new CryptoError(
        ErrorCode.INVALID_ARGUMENT,
        "options.ttl must be a positive number of seconds or a duration string ('15m', '1h', '24h', '7d')",
      );
    }
    const n = Number(m[1]);
    if (n <= 0) {
      throw new CryptoError(ErrorCode.INVALID_ARGUMENT, 'options.ttl duration must be positive');
    }
    return n * DURATION_UNITS[m[2]];
  }
  throw new CryptoError(ErrorCode.INVALID_ARGUMENT, 'options.ttl must be a number of seconds or a duration string');
}
