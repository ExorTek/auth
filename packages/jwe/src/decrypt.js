/**
 * Compact JWE consumption — `decrypt(token, key, options)` (RFC 7516 §5.2).
 *
 * The accepted `alg` and `enc` values are a **mandatory allowlist**: a
 * token is never trusted to pick its own algorithms. `RSA1_5` cannot
 * appear because it has no registry entry. Every integrity failure —
 * bad tag, wrong key, tampered segment — collapses to a single
 * {@link ErrorCode.DECRYPTION_FAILED} so nothing leaks to an attacker.
 */

import { isArray, isString } from '@exortek/shared/predicates';
import { lookup as lookupAlg } from './internal/algorithms.js';
import { lookup as lookupEnc } from './internal/encryptions.js';
import { unwrapCek } from './internal/keymgmt.js';
import { contentDecrypt } from './internal/content.js';
import { assertHeaderObject, checkCrit, decodePlaintext, enforceExpiry } from './internal/common.js';
import { _splitCompact } from './decode.js';
import { decode as b64uDecode, decodeJson as b64uDecodeJson } from './internal/base64url.js';
import { assertObject } from './internal/guards.js';
import { JweError, ErrorCode } from './internal/errors.js';

/**
 * @typedef {import('./internal/keys.js').KeyInput} KeyInput
 */

/**
 * @typedef {Object} DecryptOptions
 * @property {string[]} alg  Allowlist of accepted key-management algorithms
 *   (REQUIRED, non-empty). Omitting it raises {@link ErrorCode.MISSING_ALG_ALLOWLIST}.
 * @property {string[]} enc  Allowlist of accepted content-encryption
 *   algorithms (REQUIRED, non-empty).
 * @property {number} [maxTokenSize=8192]  Reject larger tokens with
 *   {@link ErrorCode.TOKEN_TOO_LARGE} before doing any crypto.
 * @property {string[]} [knownCriticalHeaders]  `crit` params this caller understands.
 * @property {number} [clockTolerance=0]  Seconds of leeway when enforcing `exp`.
 */

/**
 * @typedef {Object} DecryptResult
 * @property {Record<string, unknown>} protectedHeader
 * @property {unknown} payload  Parsed JSON when the plaintext is JSON, else the raw `Buffer`.
 */

/**
 * Decrypt a compact JWE.
 *
 * @param {string} token
 * @param {KeyInput} key  The recipient key — a private key / JWK for
 *   RSA-OAEP and ECDH-ES, symmetric key material for AES-KW and `dir`.
 * @param {DecryptOptions} options
 * @returns {Promise<DecryptResult>}
 */
export async function decrypt(token, key, options) {
  assertObject(options, 'decrypt.options');
  const algAllowlist = requireAllowlist(options.alg, ErrorCode.MISSING_ALG_ALLOWLIST, 'alg');
  const encAllowlist = requireAllowlist(options.enc, ErrorCode.MISSING_ENC_ALLOWLIST, 'enc');

  const maxTokenSize = options.maxTokenSize ?? 8192;
  if (typeof token === 'string' && token.length > maxTokenSize) {
    throw new JweError(ErrorCode.TOKEN_TOO_LARGE, `token is ${token.length} chars, over the ${maxTokenSize} limit.`);
  }

  const { encHeader, encKey, encIv, encCiphertext, encTag } = _splitCompact(token);
  const header = assertHeaderObject(b64uDecodeJson(encHeader));

  if (!isString(header.alg) || !algAllowlist.includes(/** @type {string} */ (header.alg))) {
    throw new JweError(
      ErrorCode.ALGORITHM_MISMATCH,
      `token "alg" ${JSON.stringify(header.alg)} is not in the allowlist [${algAllowlist.join(', ')}].`,
    );
  }
  if (!isString(header.enc) || !encAllowlist.includes(/** @type {string} */ (header.enc))) {
    throw new JweError(
      ErrorCode.ENCRYPTION_MISMATCH,
      `token "enc" ${JSON.stringify(header.enc)} is not in the allowlist [${encAllowlist.join(', ')}].`,
    );
  }
  checkCrit(header, options);

  const alg = lookupAlg(/** @type {string} */ (header.alg));
  const enc = lookupEnc(/** @type {string} */ (header.enc));

  const encryptedKey = encKey === '' ? Buffer.alloc(0) : b64uDecode(encKey);
  const cek = unwrapCek(alg, enc, key, header, encryptedKey);

  const aad = Buffer.from(encHeader, 'ascii');
  const plaintext = contentDecrypt(enc, cek, b64uDecode(encIv), b64uDecode(encCiphertext), b64uDecode(encTag), aad);

  const payload = decodePlaintext(plaintext);
  enforceExpiry(payload, options);

  return { protectedHeader: header, payload };
}

/**
 * @param {unknown} allowlist
 * @param {string} code
 * @param {string} label
 * @returns {string[]}
 */
function requireAllowlist(allowlist, code, label) {
  if (!isArray(allowlist) || allowlist.length === 0 || !allowlist.every(isString)) {
    throw new JweError(code, `decrypt requires a non-empty options.${label} allowlist (string[]).`);
  }
  return /** @type {string[]} */ (allowlist);
}
