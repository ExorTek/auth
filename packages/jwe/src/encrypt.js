/**
 * Compact JWE production — `encrypt(payload, key, options)` (RFC 7516 §3.1 / §7.1).
 *
 * Generates (or derives) the Content Encryption Key via the `alg`
 * key-management step, encrypts the payload under the `enc` AEAD binding
 * the protected header as Additional Authenticated Data, and assembles
 * the five-segment compact serialization.
 */

import { lookup as lookupAlg } from './internal/algorithms.js';
import { lookup as lookupEnc } from './internal/encryptions.js';
import { wrapCek } from './internal/keymgmt.js';
import { contentEncrypt } from './internal/content.js';
import { encodePlaintext } from './internal/common.js';
import { encode as b64uEncode, encodeJson as b64uEncodeJson } from './internal/base64url.js';
import { assertObject, assertNonEmptyString } from './internal/guards.js';

/**
 * @typedef {import('./internal/keys.js').KeyInput} KeyInput
 */

/**
 * @typedef {Object} EncryptOptions
 * @property {string} alg  Key-management algorithm (REQUIRED) — e.g.
 *   `'RSA-OAEP-256'`, `'ECDH-ES+A256KW'`, `'A256KW'`, `'dir'`.
 * @property {string} enc  Content-encryption algorithm (REQUIRED) — e.g.
 *   `'A256GCM'`, `'A128CBC-HS256'`.
 * @property {string} [kid]  Key ID written to the protected header.
 * @property {Record<string, unknown>} [header]  Extra protected-header
 *   params, merged first; `alg` / `enc` / `kid` and the key-management
 *   params (`epk` / `apu` / `apv`) always win over them.
 * @property {string | number} [expiresIn]  When the payload is a JSON
 *   object, stamp an `exp` claim this far in the future (duration string
 *   like `'1h'`, or milliseconds).
 * @property {string | Buffer | Uint8Array} [apu]  ECDH-ES Agreement
 *   PartyUInfo. Ignored by non-ECDH algorithms.
 * @property {string | Buffer | Uint8Array} [apv]  ECDH-ES Agreement PartyVInfo.
 */

/**
 * Encrypt a payload into a compact JWE string.
 *
 * @param {unknown} payload  A JSON-serialisable value, a string, or raw
 *   bytes (`Buffer` / `Uint8Array`).
 * @param {KeyInput} key  The recipient key — a public key / JWK for
 *   RSA-OAEP and ECDH-ES, symmetric key material for AES-KW and `dir`.
 * @param {EncryptOptions} options
 * @returns {Promise<string>}
 */
export async function encrypt(payload, key, options) {
  assertObject(options, 'encrypt.options');
  assertNonEmptyString(options.alg, 'encrypt.options.alg');
  assertNonEmptyString(options.enc, 'encrypt.options.enc');

  const alg = lookupAlg(options.alg);
  const enc = lookupEnc(options.enc);

  const plaintext = encodePlaintext(payload, options);
  const { cek, encryptedKey, header: kmHeader } = wrapCek(alg, enc, key, { apu: options.apu, apv: options.apv });

  const protectedHeader = { ...(options.header ?? {}) };
  protectedHeader.alg = options.alg;
  protectedHeader.enc = options.enc;
  if (options.kid !== undefined) {
    protectedHeader.kid = options.kid;
  }
  Object.assign(protectedHeader, kmHeader);

  const encodedProtected = b64uEncodeJson(protectedHeader);
  const aad = Buffer.from(encodedProtected, 'ascii');
  const { iv, ciphertext, tag } = contentEncrypt(enc, cek, plaintext, aad);

  return [encodedProtected, b64uEncode(encryptedKey), b64uEncode(iv), b64uEncode(ciphertext), b64uEncode(tag)].join(
    '.',
  );
}
