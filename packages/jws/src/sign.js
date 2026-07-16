/**
 * JWS Compact Serialization signing (RFC 7515 §7.1).
 *
 * `alg` is **mandatory** on every call — there is no default. `none`
 * is refused up front with a dedicated error code so the diagnostic is
 * actionable rather than "unsupported algorithm".
 *
 * `signDetached` and `b64: false` land in follow-up commits (RFC 7515
 * Appendix F and RFC 7797 respectively).
 */

import { JwsError, ErrorCode } from './internal/errors.js';
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
  if (options == null || typeof options !== 'object') {
    throw new JwsError(ErrorCode.INVALID_ARGUMENT, 'sign: options object is required');
  }
  const alg = options.alg;
  if (typeof alg !== 'string' || alg.length === 0) {
    throw new JwsError(ErrorCode.INVALID_ARGUMENT, 'sign: `alg` is required and must be a string');
  }
  if (alg === 'none') {
    throw new JwsError(
      ErrorCode.ALGORITHM_NONE_FORBIDDEN,
      'sign: alg "none" is refused by this library — no configuration can enable it (RFC 8725 §3.1)',
    );
  }

  const meta = lookupAlg(alg);
  const keyObj = await normalizeKey(key, alg, 'sign');

  const header = _buildHeader(alg, options);
  assertCritSign(header.crit, header);

  const encHeader = b64uEncodeJson(header);
  const encPayload = _encodePayload(payload);
  const signingInput = Buffer.from(`${encHeader}.${encPayload}`, 'utf8');
  const signature = await meta.sign(keyObj, signingInput);
  const encSig = b64uEncode(signature);

  return `${encHeader}.${encPayload}.${encSig}`;
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
  if (options == null || typeof options !== 'object') {
    throw new JwsError(ErrorCode.INVALID_ARGUMENT, 'signDetached: options object is required');
  }
  const alg = options.alg;
  if (typeof alg !== 'string' || alg.length === 0) {
    throw new JwsError(ErrorCode.INVALID_ARGUMENT, 'signDetached: `alg` is required and must be a string');
  }
  if (alg === 'none') {
    throw new JwsError(
      ErrorCode.ALGORITHM_NONE_FORBIDDEN,
      'signDetached: alg "none" is refused by this library — no configuration can enable it (RFC 8725 §3.1)',
    );
  }

  const meta = lookupAlg(alg);
  const keyObj = await normalizeKey(key, alg, 'sign');

  const header = _buildHeader(alg, options);
  assertCritSign(header.crit, header);

  const encHeader = b64uEncodeJson(header);
  const payloadBuf = Buffer.from(payload.buffer, payload.byteOffset, payload.byteLength);
  const encPayload = b64uEncode(payloadBuf);

  // RFC 7515 §5.1 signing-input construction — identical whether the
  // payload segment is emitted or not.
  const signingInput = Buffer.from(`${encHeader}.${encPayload}`, 'utf8');
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
  if (options.header && typeof options.header === 'object') {
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
 * Serialise the payload into the base64url segment. Buffers/Uint8Arrays
 * are copied byte-for-byte; strings are UTF-8; everything else goes
 * through `JSON.stringify`.
 *
 * @param {unknown} payload
 * @returns {string}
 */
function _encodePayload(payload) {
  if (Buffer.isBuffer(payload) || payload instanceof Uint8Array) {
    return b64uEncode(Buffer.from(payload));
  }
  if (typeof payload === 'string') {
    return Buffer.from(payload, 'utf8').toString('base64url');
  }
  if (payload === undefined) {
    throw new JwsError(ErrorCode.INVALID_PAYLOAD, 'sign: payload is required');
  }
  return b64uEncodeJson(payload);
}
