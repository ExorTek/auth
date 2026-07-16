/**
 * JWS Compact Serialization verification (RFC 7515 §7.1).
 *
 * The `alg` allowlist is **mandatory** on every call — omission raises
 * {@link ErrorCode.MISSING_ALG_ALLOWLIST}. `alg: 'none'` on the token
 * is refused up front with {@link ErrorCode.ALGORITHM_NONE_FORBIDDEN};
 * no flag can enable it.
 *
 * `verifyDetached` lands in the detached-content commit.
 */

import { JwsError, ErrorCode } from './internal/errors.js';
import { lookup as lookupAlg } from './internal/algorithms.js';
import { assertVerifySide as assertCritVerify } from './internal/crit.js';
import { decode as b64uDecode, decodeJson as b64uDecodeJson } from './internal/base64url.js';
import { resolveKey } from './internal/resolver.js';
import { _splitCompact, _decodePayload } from './decode.js';

/**
 * @typedef {import('./internal/keys.js').KeyInput} KeyInput
 * @typedef {import('./internal/resolver.js').KeyResolverFn} KeyResolverFn
 *
 * @typedef {Object} VerifyOptions
 * @property {string[]} alg                                  REQUIRED. Accepted JOSE algorithm identifiers.
 * @property {Iterable<string>} [knownCriticalHeaders]       Extra `crit` names the verifier is prepared to process.
 * @property {number} [maxTokenSize]                         Default 8192 bytes. Larger tokens raise `TOKEN_TOO_LARGE`.
 *
 * @typedef {Object} VerifyResult
 * @property {Record<string, unknown>} header
 * @property {unknown} payload
 * @property {string | undefined} kid
 */

const DEFAULT_MAX_TOKEN_SIZE = 8192;

/**
 * Verify a compact JWS.
 *
 * @param {string} token
 * @param {KeyInput | KeyInput[] | KeyResolverFn} keyish
 * @param {VerifyOptions} options
 * @returns {Promise<VerifyResult>}
 */
export async function verify(token, keyish, options) {
  const allowlist = _requireAllowlist(options);
  _sizeCheck(token, options?.maxTokenSize ?? DEFAULT_MAX_TOKEN_SIZE);

  const { encHeader, encPayload, encSig } = _splitCompact(token);
  const header = /** @type {Record<string, unknown>} */ (b64uDecodeJson(encHeader, 'header'));
  _assertHeaderShape(header);

  const alg = /** @type {string} */ (header.alg);
  _assertAlgAllowed(alg, allowlist);

  assertCritVerify(header.crit, header, options.knownCriticalHeaders);

  const meta = lookupAlg(alg);
  const keyObj = await resolveKey(keyish, header, alg);

  const signingInput = _buildSigningInput(encHeader, encPayload, header);
  const signature = b64uDecode(encSig);

  const ok = await meta.verify(keyObj, signingInput, signature);
  if (!ok) {
    throw new JwsError(ErrorCode.INVALID_SIGNATURE, `verify: signature does not match (alg=${alg})`);
  }

  const payload = _decodePayload(header, encPayload);
  return { header, payload, kid: /** @type {string | undefined} */ (header.kid) };
}

/**
 * Verify a detached-content JWS. Not yet implemented — arrives in the
 * follow-up commit.
 *
 * @param {string} _token
 * @param {Buffer | Uint8Array} _detachedPayload
 * @param {KeyInput | KeyInput[] | KeyResolverFn} _keyish
 * @param {VerifyOptions} _options
 * @returns {Promise<VerifyResult>}
 */
export async function verifyDetached(_token, _detachedPayload, _keyish, _options) {
  throw new JwsError(
    ErrorCode.INVALID_ARGUMENT,
    'verifyDetached: not yet implemented — arrives in the detached-content commit',
  );
}

/**
 * @param {VerifyOptions | undefined} options
 * @returns {string[]}
 */
function _requireAllowlist(options) {
  if (options == null || typeof options !== 'object') {
    throw new JwsError(
      ErrorCode.MISSING_ALG_ALLOWLIST,
      'verify: options.alg is required — pass an explicit allowlist array (e.g. { alg: ["ES256"] })',
    );
  }
  const allow = options.alg;
  if (!Array.isArray(allow) || allow.length === 0 || allow.some(a => typeof a !== 'string')) {
    throw new JwsError(
      ErrorCode.MISSING_ALG_ALLOWLIST,
      'verify: options.alg must be a non-empty array of algorithm identifier strings',
    );
  }
  return /** @type {string[]} */ (allow);
}

/**
 * @param {string} token
 * @param {number} max
 */
function _sizeCheck(token, max) {
  if (typeof token !== 'string') {
    return;
  } // let the split step throw INVALID_TOKEN with a clean message
  const bytes = Buffer.byteLength(token, 'utf8');
  if (bytes > max) {
    throw new JwsError(ErrorCode.TOKEN_TOO_LARGE, `verify: token is ${bytes} bytes, exceeds maxTokenSize=${max}`);
  }
}

/**
 * @param {Record<string, unknown>} header
 */
function _assertHeaderShape(header) {
  if (header == null || typeof header !== 'object' || Array.isArray(header)) {
    throw new JwsError(ErrorCode.INVALID_HEADER, 'verify: protected header must be a JSON object');
  }
  if (typeof header.alg !== 'string') {
    throw new JwsError(ErrorCode.INVALID_HEADER, 'verify: protected header must carry an `alg` string');
  }
}

/**
 * @param {string} alg
 * @param {string[]} allowlist
 */
function _assertAlgAllowed(alg, allowlist) {
  if (alg === 'none') {
    throw new JwsError(
      ErrorCode.ALGORITHM_NONE_FORBIDDEN,
      'verify: token uses alg "none" — refused unconditionally (RFC 8725 §3.1)',
    );
  }
  if (!allowlist.includes(alg)) {
    throw new JwsError(
      ErrorCode.ALGORITHM_MISMATCH,
      `verify: token alg ${JSON.stringify(alg)} is not in the caller's allowlist [${allowlist.map(a => JSON.stringify(a)).join(', ')}]`,
    );
  }
}

/**
 * Build the octet string that was actually signed. RFC 7515 §5.1 for
 * standard b64 payloads; RFC 7797 §3 for b64:false where the payload
 * bytes go in unencoded.
 *
 * @param {string} encHeader
 * @param {string} encPayload
 * @param {Record<string, unknown>} header
 * @returns {Buffer}
 */
function _buildSigningInput(encHeader, encPayload, header) {
  if (header.b64 === false) {
    return Buffer.concat([Buffer.from(`${encHeader}.`, 'utf8'), Buffer.from(encPayload, 'utf8')]);
  }
  return Buffer.from(`${encHeader}.${encPayload}`, 'utf8');
}
