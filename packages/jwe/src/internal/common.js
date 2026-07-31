/**
 * Cross-surface helpers shared by the compact and JSON serializations —
 * plaintext ↔ bytes conversion, optional `exp` stamping / enforcement,
 * and `crit` (RFC 7516 §4.1.13) validation.
 */

import { isObject, isBytes, isArray, isString, isNumber } from '@exortek/shared/predicates';
import { parseDuration } from '@exortek/shared/duration';
import { JweError, ErrorCode } from './errors.js';

/** Header parameters this package understands and processes itself. */
const UNDERSTOOD_HEADERS = new Set(['alg', 'enc', 'epk', 'apu', 'apv', 'kid', 'crit', 'zip']);

/**
 * @param {unknown} value
 * @returns {boolean} True for a plain (claims-style) object — not bytes, not an array.
 */
function isPlainObject(value) {
  return isObject(value) && !isBytes(value) && !isArray(value);
}

/**
 * Encode a payload into the plaintext byte string, stamping `exp` when
 * `expiresIn` is set and the payload is a JSON object.
 *
 * @param {unknown} payload
 * @param {{ expiresIn?: string | number }} options
 * @returns {Buffer}
 */
export function encodePlaintext(payload, options) {
  if (isBytes(payload)) {
    return Buffer.from(/** @type {Buffer | Uint8Array} */ (payload));
  }
  if (isString(payload)) {
    return Buffer.from(/** @type {string} */ (payload), 'utf8');
  }

  let value = payload;
  if (options.expiresIn !== undefined && isPlainObject(payload)) {
    const exp = Math.floor((Date.now() + parseDuration(options.expiresIn)) / 1000);
    value = { .../** @type {Record<string, unknown>} */ (payload), exp };
  }
  return Buffer.from(JSON.stringify(value), 'utf8');
}

/**
 * Interpret recovered plaintext — parsed JSON when it is valid JSON, the
 * raw `Buffer` otherwise (binary payloads round-trip untouched).
 *
 * @param {Buffer} plaintext
 * @returns {unknown}
 */
export function decodePlaintext(plaintext) {
  try {
    return JSON.parse(plaintext.toString('utf8'));
  } catch {
    return plaintext;
  }
}

/**
 * Enforce an `exp` claim if the decrypted payload carries one.
 *
 * @param {unknown} payload
 * @param {{ clockTolerance?: number }} options
 */
export function enforceExpiry(payload, options) {
  if (!isPlainObject(payload)) {
    return;
  }
  const exp = /** @type {Record<string, unknown>} */ (payload).exp;
  if (!isNumber(exp)) {
    return;
  }
  const now = Math.floor(Date.now() / 1000);
  const tolerance = options.clockTolerance ?? 0;
  if (now > /** @type {number} */ (exp) + tolerance) {
    throw new JweError(
      ErrorCode.TOKEN_EXPIRED,
      `token expired at ${new Date(/** @type {number} */ (exp) * 1000).toISOString()}.`,
    );
  }
}

/**
 * Validate the `crit` header (RFC 7516 §4.1.13): every listed parameter
 * must be understood by the caller (`knownCriticalHeaders`) and actually
 * present in the header.
 *
 * @param {Record<string, unknown>} header
 * @param {{ knownCriticalHeaders?: string[] }} options
 */
export function checkCrit(header, options) {
  const crit = header.crit;
  if (crit === undefined) {
    return;
  }
  if (!isArray(crit)) {
    throw new JweError(ErrorCode.INVALID_HEADER, '"crit" must be an array of header parameter names.');
  }
  const known = new Set(options.knownCriticalHeaders ?? []);
  for (const name of /** @type {unknown[]} */ (crit)) {
    if (!isString(name)) {
      throw new JweError(ErrorCode.INVALID_HEADER, '"crit" entries must be strings.');
    }
    if (UNDERSTOOD_HEADERS.has(name) && name !== 'crit') {
      continue;
    }
    if (!known.has(name)) {
      throw new JweError(
        ErrorCode.CRIT_UNSUPPORTED,
        `unsupported critical header parameter "${name}" — pass it in knownCriticalHeaders if you handle it.`,
      );
    }
    if (!(name in header)) {
      throw new JweError(
        ErrorCode.INVALID_HEADER,
        `critical header parameter "${name}" is listed in "crit" but absent.`,
      );
    }
  }
}

/**
 * Assert a decoded protected header is a JSON object.
 *
 * @param {unknown} header
 * @returns {Record<string, unknown>}
 */
export function assertHeaderObject(header) {
  if (!isPlainObject(header)) {
    throw new JweError(ErrorCode.INVALID_HEADER, 'protected header is not a JSON object.');
  }
  return /** @type {Record<string, unknown>} */ (header);
}
