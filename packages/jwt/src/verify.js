/**
 * JWT verification (RFC 7519 + RFC 8725). Signature check + full claims
 * validation (`exp`, `nbf`, `iat`, `iss`, `aud`, `sub`, `nonce`, `typ`,
 * `maxAge`, `requiredClaims`, `requiredScopes`).
 *
 * `alg` allowlist is **mandatory**. `alg: 'none'` is refused. `peek`
 * exposes a signature-verified payload without any claim checks — for
 * audit / logging where you need identity before token-lifecycle
 * logic. Never gate authorisation on `peek`.
 */

import { isArray, isObject, isString } from '@exortek/shared/predicates';

import { JwtError, ErrorCode } from './internal/errors.js';
import { lookup as lookupAlg } from './internal/algorithms.js';
import { assertVerifySide as assertCritVerify } from './internal/crit.js';
import { decode as b64uDecode, decodeJson as b64uDecodeJson } from './internal/base64url.js';
import { resolveKey } from './internal/resolver.js';
import { _splitCompact } from './decode.js';
import { validateClaims } from './claims.js';

/**
 * @typedef {import('./internal/keys.js').KeyInput} KeyInput
 * @typedef {import('./internal/resolver.js').KeyResolverFn} KeyResolverFn
 * @typedef {import('./claims.js').ClaimsOptions} ClaimsOptions
 *
 * @typedef {ClaimsOptions & {
 *   alg: string[],
 *   knownCriticalHeaders?: Iterable<string>,
 *   maxTokenSize?: number,
 * }} VerifyOptions
 *
 * @typedef {Object} VerifyResult
 * @property {Record<string, unknown>} header
 * @property {Record<string, unknown>} payload
 * @property {string | undefined} kid
 */

const DEFAULT_MAX_TOKEN_SIZE = 8192;

/**
 * @param {string} token
 * @param {KeyInput | KeyInput[] | KeyResolverFn} keyish
 * @param {VerifyOptions} options
 * @returns {Promise<VerifyResult>}
 */
export async function verify(token, keyish, options) {
  const { header, payload, kid } = await _verifySignature(token, keyish, options);
  await validateClaims(payload, header, options);
  return { header, payload, kid };
}

/**
 * Verify the signature but **skip claim validation**. Use for audit
 * paths where you need a trustworthy identity even from an expired
 * token. Never gate authorisation on this — use `verify` for that.
 *
 * @param {string} token
 * @param {KeyInput | KeyInput[] | KeyResolverFn} keyish
 * @param {Pick<VerifyOptions, 'alg' | 'knownCriticalHeaders' | 'maxTokenSize'>} options
 * @returns {Promise<VerifyResult>}
 */
export async function peek(token, keyish, options) {
  return _verifySignature(token, keyish, /** @type {VerifyOptions} */ (options));
}

/**
 * Shared signature-verification path used by both `verify` and `peek`.
 * Returns the parsed header + payload + kid on success without running
 * any claim checks.
 *
 * @param {string} token
 * @param {KeyInput | KeyInput[] | KeyResolverFn} keyish
 * @param {VerifyOptions} options
 * @returns {Promise<VerifyResult>}
 */
async function _verifySignature(token, keyish, options) {
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

  const signingInput = Buffer.from(`${encHeader}.${encPayload}`, 'utf8');
  const signature = b64uDecode(encSig);

  const ok = await meta.verify(keyObj, signingInput, signature);
  if (!ok) {
    throw new JwtError(ErrorCode.INVALID_SIGNATURE, `verify: signature does not match (alg=${alg})`);
  }

  const payload = /** @type {Record<string, unknown>} */ (b64uDecodeJson(encPayload, 'payload'));
  if (!isObject(payload)) {
    throw new JwtError(ErrorCode.INVALID_PAYLOAD, 'verify: JWT payload must be a JSON object');
  }
  return { header, payload, kid: /** @type {string | undefined} */ (header.kid) };
}

/**
 * @param {VerifyOptions | undefined} options
 * @returns {string[]}
 */
function _requireAllowlist(options) {
  if (options == null || typeof options !== 'object') {
    throw new JwtError(
      ErrorCode.MISSING_ALG_ALLOWLIST,
      'verify: options.alg is required — pass an explicit allowlist array (e.g. { alg: ["ES256"] })',
    );
  }
  const allow = options.alg;
  if (!isArray(allow) || allow.length === 0 || allow.some(a => !isString(a))) {
    throw new JwtError(
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
  }
  const bytes = Buffer.byteLength(token, 'utf8');
  if (bytes > max) {
    throw new JwtError(ErrorCode.TOKEN_TOO_LARGE, `verify: token is ${bytes} bytes, exceeds maxTokenSize=${max}`);
  }
}

/**
 * @param {Record<string, unknown>} header
 */
function _assertHeaderShape(header) {
  if (!isObject(header)) {
    throw new JwtError(ErrorCode.INVALID_HEADER, 'verify: protected header must be a JSON object');
  }
  if (typeof header.alg !== 'string') {
    throw new JwtError(ErrorCode.INVALID_HEADER, 'verify: protected header must carry an `alg` string');
  }
}

/**
 * @param {string} alg
 * @param {string[]} allowlist
 */
function _assertAlgAllowed(alg, allowlist) {
  if (alg === 'none') {
    throw new JwtError(
      ErrorCode.ALGORITHM_NONE_FORBIDDEN,
      'verify: token uses alg "none" — refused unconditionally (RFC 8725 §3.1)',
    );
  }
  if (!allowlist.includes(alg)) {
    throw new JwtError(
      ErrorCode.ALGORITHM_MISMATCH,
      `verify: token alg ${JSON.stringify(alg)} is not in the caller's allowlist [${allowlist.map(a => JSON.stringify(a)).join(', ')}]`,
    );
  }
}
