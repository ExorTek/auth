/**
 * JWS Compact Serialization signing (RFC 7515 §7.1) plus the unencoded
 * payload extension (RFC 7797) and detached content (RFC 7515 §F).
 *
 * `alg` is **mandatory** on every call — there is no default. `none`
 * is refused up front with a dedicated error code so the diagnostic is
 * actionable rather than "unsupported algorithm".
 */

import { isObject } from '@exortek/shared/predicates';

import { JwsError, ErrorCode } from './internal/errors.js';
import { assertNonEmptyString, assertObject } from './internal/guards.js';
import { lookup as lookupAlg } from './internal/algorithms.js';
import { normalizeKey } from './internal/keys.js';
import { assertSignSide as assertCritSign } from './internal/crit.js';
import { encode as b64uEncode, encodeJson as b64uEncodeJson } from './internal/base64url.js';

/**
 * @typedef {import('./internal/keys.js').KeyInput} KeyInput
 *
 * @typedef {Object} SignOptions
 * @property {string} alg                                 REQUIRED. JOSE algorithm identifier.
 * @property {string} [kid]                               `kid` header shortcut.
 * @property {Record<string, unknown>} [header]           Extra protected header parameters (merged after `alg` / `kid`).
 * @property {string[]} [crit]                            Marks header names as critical (RFC 7515 §4.1.11).
 * @property {boolean} [b64]                              RFC 7797 unencoded-payload switch. Default `true` (standard base64url payload).
 *                                                       When `false`, the compact segment carries the raw payload; `crit`
 *                                                       gets `"b64"` auto-injected per RFC 7797 §5.1, and the payload MUST
 *                                                       NOT contain a `.` (compact serialisation ambiguity).
 */

/**
 * Sign a payload and return a compact JWS.
 *
 * @param {unknown} payload    JSON-serialisable value, `string`, or a `Buffer` / `Uint8Array` for raw bytes.
 * @param {KeyInput} key
 * @param {SignOptions} options
 * @returns {Promise<string>}
 */
export async function sign(payload, key, options) {
  assertObject(options, 'sign.options');
  assertNonEmptyString(options.alg, 'sign.options.alg');
  const alg = options.alg;
  if (alg === 'none') {
    throw new JwsError(
      ErrorCode.ALGORITHM_NONE_FORBIDDEN,
      'sign: alg "none" is refused by this library — no configuration can enable it (RFC 8725 §3.1)',
    );
  }

  const meta = lookupAlg(alg);
  const keyObj = await normalizeKey(key, alg, 'sign');

  const b64 = options.b64 !== false;
  const header = _buildHeader(alg, options);
  if (!b64) {
    header.b64 = false;
    header.crit = _mergeCritForB64False(header.crit);
  }
  assertCritSign(header.crit, header);

  const encHeader = b64uEncodeJson(header);
  const { segment, signingInput } = _prepareCompact(payload, encHeader, b64);
  const signature = await meta.sign(keyObj, signingInput);
  const encSig = b64uEncode(signature);

  return `${encHeader}.${segment}.${encSig}`;
}

/**
 * Sign with the RFC 7515 Appendix F detached-content variant. The
 * returned `token` carries an empty payload segment; the caller keeps
 * the `detached` bytes and ships them out-of-band, then hands both
 * back to {@link verifyDetached}. Handy for large uploads where the
 * payload never lives in memory at once but a small signature does.
 *
 * @param {Buffer | Uint8Array} payload
 * @param {KeyInput} key
 * @param {SignOptions} options
 * @returns {Promise<{ token: string, detached: Buffer }>}
 */
export async function signDetached(payload, key, options) {
  if (!Buffer.isBuffer(payload) && !(payload instanceof Uint8Array)) {
    throw new JwsError(
      ErrorCode.INVALID_PAYLOAD,
      'signDetached: payload must be a Buffer or Uint8Array — the caller is responsible for the byte encoding',
    );
  }
  assertObject(options, 'signDetached.options');
  assertNonEmptyString(options.alg, 'signDetached.options.alg');
  const alg = options.alg;
  if (alg === 'none') {
    throw new JwsError(
      ErrorCode.ALGORITHM_NONE_FORBIDDEN,
      'signDetached: alg "none" is refused by this library — no configuration can enable it (RFC 8725 §3.1)',
    );
  }

  const meta = lookupAlg(alg);
  const keyObj = await normalizeKey(key, alg, 'sign');

  const b64 = options.b64 !== false;
  const header = _buildHeader(alg, options);
  if (!b64) {
    header.b64 = false;
    header.crit = _mergeCritForB64False(header.crit);
  }
  assertCritSign(header.crit, header);

  const encHeader = b64uEncodeJson(header);
  const payloadBuf = Buffer.from(payload.buffer, payload.byteOffset, payload.byteLength);

  // RFC 7515 §5.1 signing-input construction. b64:false (RFC 7797) feeds
  // the raw payload bytes into the signing input; the emitted token
  // still has an empty payload segment because it is detached.
  const signingInput = b64
    ? Buffer.from(`${encHeader}.${payloadBuf.toString('base64url')}`, 'utf8')
    : Buffer.concat([Buffer.from(`${encHeader}.`, 'utf8'), payloadBuf]);
  const signature = await meta.sign(keyObj, signingInput);
  const encSig = b64uEncode(signature);

  return { token: `${encHeader}..${encSig}`, detached: payloadBuf };
}

/**
 * @param {string} alg
 * @param {SignOptions} options
 * @returns {Record<string, unknown>}
 */
function _buildHeader(alg, options) {
  /** @type {Record<string, unknown>} */
  const header = { alg };
  if (options.kid !== undefined) {
    header.kid = options.kid;
  }
  if (isObject(options.header)) {
    for (const [k, v] of Object.entries(options.header)) {
      if (k === 'alg') {
        continue;
      } // caller's `header.alg` must not override the top-level.
      header[k] = v;
    }
  }
  if (options.crit !== undefined) {
    header.crit = Array.isArray(options.crit) ? [...options.crit] : options.crit;
  }
  return header;
}

/**
 * Build the compact payload segment + signing input.
 *
 *   - `b64 === true` (default) → segment is base64url of the payload bytes;
 *     signing input is `${encHeader}.${segment}`.
 *   - `b64 === false` (RFC 7797) → segment is the raw payload string;
 *     signing input hashes the raw bytes directly. `.` in the payload is
 *     rejected because the compact form has no way to parse it back.
 *
 * @param {unknown} payload
 * @param {string} encHeader
 * @param {boolean} b64
 * @returns {{ segment: string, signingInput: Buffer }}
 */
function _prepareCompact(payload, encHeader, b64) {
  if (payload === undefined) {
    throw new JwsError(ErrorCode.INVALID_PAYLOAD, 'sign: payload is required');
  }
  const bytes = _payloadBytes(payload);
  if (b64) {
    const segment = bytes.toString('base64url');
    return {
      segment,
      signingInput: Buffer.from(`${encHeader}.${segment}`, 'utf8'),
    };
  }
  const segment = bytes.toString('utf8');
  if (segment.includes('.')) {
    throw new JwsError(
      ErrorCode.INVALID_PAYLOAD,
      'sign: b64:false payload must not contain "." — compact serialisation cannot disambiguate the payload segment (RFC 7797 §5.2)',
    );
  }
  return {
    segment,
    signingInput: Buffer.concat([Buffer.from(`${encHeader}.`, 'utf8'), bytes]),
  };
}

/**
 * Convert an arbitrary payload into raw bytes ready for signing.
 * Buffers / Uint8Arrays pass through; strings are UTF-8; everything else
 * goes through `JSON.stringify`.
 *
 * @param {unknown} payload
 * @returns {Buffer}
 */
function _payloadBytes(payload) {
  if (Buffer.isBuffer(payload)) {
    return payload;
  }
  if (payload instanceof Uint8Array) {
    return Buffer.from(payload.buffer, payload.byteOffset, payload.byteLength);
  }
  if (typeof payload === 'string') {
    return Buffer.from(payload, 'utf8');
  }
  return Buffer.from(JSON.stringify(payload), 'utf8');
}

/**
 * When the caller opts into `b64: false`, RFC 7797 §5.1 requires the
 * `crit` header to advertise `b64` so verifiers unaware of the extension
 * refuse the token. Callers may pass their own `crit` list; we merge
 * `b64` into it.
 *
 * @param {unknown} existing
 * @returns {string[]}
 */
function _mergeCritForB64False(existing) {
  if (existing === undefined) {
    return ['b64'];
  }
  if (!Array.isArray(existing)) {
    throw new JwsError(ErrorCode.INVALID_HEADER, 'sign: crit must be a JSON array of strings');
  }
  return existing.includes('b64') ? /** @type {string[]} */ (existing) : [.../** @type {string[]} */ (existing), 'b64'];
}
