/**
 * JWE JSON serialization — General + Flattened (RFC 7516 §3.2 / §7.2).
 *
 * The content is encrypted once under a single CEK; each recipient's
 * per-recipient header carries its own `alg` (and `epk` / `apu` / `apv`
 * for ECDH-ES) while the shared `enc` lives in the protected header. The
 * `dir` and bare `ECDH-ES` algorithms fix the CEK themselves, so they
 * are only valid as the sole recipient.
 */

import { randomBytes } from 'node:crypto';
import { isArray, isObject, isString } from '@exortek/shared/predicates';
import { lookup as lookupAlg } from './internal/algorithms.js';
import { lookup as lookupEnc } from './internal/encryptions.js';
import { wrapCek, unwrapCek } from './internal/keymgmt.js';
import { contentEncrypt, contentDecrypt } from './internal/content.js';
import { assertHeaderObject, checkCrit, decodePlaintext, encodePlaintext, enforceExpiry } from './internal/common.js';
import {
  encode as b64uEncode,
  decode as b64uDecode,
  encodeJson as b64uEncodeJson,
  decodeJson as b64uDecodeJson,
} from './internal/base64url.js';
import { assertObject } from './internal/guards.js';
import { JweError, ErrorCode } from './internal/errors.js';

/**
 * @typedef {import('./internal/keys.js').KeyInput} KeyInput
 * @typedef {import('./decrypt.js').DecryptResult} DecryptResult
 */

/**
 * @typedef {Object} JweRecipientInput
 * @property {KeyInput} key
 * @property {string} alg  Key-management algorithm for this recipient.
 * @property {string} [kid]
 * @property {Record<string, unknown>} [header]  Extra per-recipient header params.
 * @property {string | Buffer | Uint8Array} [apu]
 * @property {string | Buffer | Uint8Array} [apv]
 */

/**
 * @typedef {Object} EncryptJsonOptions
 * @property {string} enc  Content-encryption algorithm (REQUIRED).
 * @property {Record<string, unknown>} [header]  Extra protected-header params.
 * @property {string | Buffer | Uint8Array} [aad]  Optional JWE AAD, bound into the tag.
 * @property {string | number} [expiresIn]
 */

/**
 * @typedef {Object} GeneralJwe
 * @property {string} protected
 * @property {Array<{ header?: Record<string, unknown>, encrypted_key: string }>} recipients
 * @property {string} iv
 * @property {string} ciphertext
 * @property {string} tag
 * @property {string} [aad]
 */

/**
 * @param {unknown} value
 * @returns {Buffer}
 */
function toBytes(value) {
  if (value === undefined || value === null) return Buffer.alloc(0);
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) return Buffer.from(value);
  if (typeof value === 'string') return Buffer.from(value, 'utf8');
  throw new JweError(ErrorCode.INVALID_ARGUMENT, 'aad must be a string, Buffer, or Uint8Array.');
}

/**
 * @param {string} encodedProtected
 * @param {string} [encodedAad]
 * @returns {Buffer}
 */
function buildAad(encodedProtected, encodedAad) {
  return Buffer.from(encodedAad === undefined ? encodedProtected : `${encodedProtected}.${encodedAad}`, 'ascii');
}

/**
 * Encrypt into the General JWE JSON serialization.
 *
 * @param {unknown} payload
 * @param {JweRecipientInput[]} recipients
 * @param {EncryptJsonOptions} options
 * @returns {Promise<GeneralJwe>}
 */
export async function encryptJson(payload, recipients, options) {
  assertObject(options, 'encryptJson.options');
  if (!isArray(recipients) || recipients.length === 0) {
    throw new JweError(ErrorCode.INVALID_ARGUMENT, 'encryptJson: recipients must be a non-empty array.');
  }
  if (!isString(options.enc)) {
    throw new JweError(ErrorCode.INVALID_ARGUMENT, 'encryptJson.options.enc is required.');
  }

  const enc = lookupEnc(options.enc);
  const plaintext = encodePlaintext(payload, options);

  const protectedHeader = { ...(options.header ?? {}), enc: options.enc };
  const encodedProtected = b64uEncodeJson(protectedHeader);
  const encodedAad = options.aad === undefined ? undefined : b64uEncode(toBytes(options.aad));
  const aad = buildAad(encodedProtected, encodedAad);

  const sharedCek = recipients.length > 1 ? randomBytes(enc.cekBytes) : undefined;
  /** @type {Buffer | undefined} */
  let cek;
  const jweRecipients = recipients.map(recipient => {
    if (!isString(recipient.alg)) {
      throw new JweError(ErrorCode.INVALID_ARGUMENT, 'encryptJson: each recipient needs a string "alg".');
    }
    const alg = lookupAlg(recipient.alg);
    const result = wrapCek(alg, enc, recipient.key, { apu: recipient.apu, apv: recipient.apv }, sharedCek);
    cek = result.cek;
    const header = { ...(recipient.header ?? {}), alg: recipient.alg };
    if (recipient.kid !== undefined) header.kid = recipient.kid;
    Object.assign(header, result.header);
    return { header, encrypted_key: b64uEncode(result.encryptedKey) };
  });

  const { iv, ciphertext, tag } = contentEncrypt(enc, /** @type {Buffer} */ (cek), plaintext, aad);

  /** @type {GeneralJwe} */
  const jwe = {
    protected: encodedProtected,
    recipients: jweRecipients,
    iv: b64uEncode(iv),
    ciphertext: b64uEncode(ciphertext),
    tag: b64uEncode(tag),
  };
  if (encodedAad !== undefined) jwe.aad = encodedAad;
  return jwe;
}

/**
 * @typedef {import('./decrypt.js').DecryptOptions} DecryptOptions
 */

/**
 * Decrypt a General or Flattened JWE JSON serialization.
 *
 * @param {GeneralJwe | Record<string, unknown>} jwe
 * @param {KeyInput} key
 * @param {DecryptOptions} options
 * @returns {Promise<DecryptResult>}
 */
export async function decryptJson(jwe, key, options) {
  assertObject(options, 'decryptJson.options');
  const algAllowlist = requireAllowlist(options.alg, ErrorCode.MISSING_ALG_ALLOWLIST, 'alg');
  const encAllowlist = requireAllowlist(options.enc, ErrorCode.MISSING_ENC_ALLOWLIST, 'enc');
  if (!isObject(jwe) || !isString(jwe.protected)) {
    throw new JweError(ErrorCode.INVALID_TOKEN, 'decryptJson: expected a JWE JSON object with a "protected" member.');
  }

  const protectedHeader = assertHeaderObject(b64uDecodeJson(/** @type {string} */ (jwe.protected)));
  const recipientList = normalizeRecipients(jwe);
  const encodedAad = jwe.aad === undefined ? undefined : /** @type {string} */ (jwe.aad);
  const aad = buildAad(/** @type {string} */ (jwe.protected), encodedAad);

  /** @type {Buffer | undefined} */
  let cek;
  /** @type {Record<string, unknown> | undefined} */
  let matchedHeader;
  /** @type {import('./internal/encryptions.js').ContentEncryptionDescriptor | undefined} */
  let matchedEnc;
  /** @type {unknown} */
  let lastError;

  for (const recipient of recipientList) {
    const header = { ...protectedHeader, ...(recipient.header ?? {}) };
    try {
      if (!isString(header.alg) || !algAllowlist.includes(/** @type {string} */ (header.alg))) {
        throw new JweError(
          ErrorCode.ALGORITHM_MISMATCH,
          `recipient "alg" ${JSON.stringify(header.alg)} is not in the allowlist.`,
        );
      }
      if (!isString(header.enc) || !encAllowlist.includes(/** @type {string} */ (header.enc))) {
        throw new JweError(
          ErrorCode.ENCRYPTION_MISMATCH,
          `"enc" ${JSON.stringify(header.enc)} is not in the allowlist.`,
        );
      }
      checkCrit(header, options);
      const alg = lookupAlg(/** @type {string} */ (header.alg));
      const enc = lookupEnc(/** @type {string} */ (header.enc));
      const encryptedKey = recipient.encrypted_key ? b64uDecode(recipient.encrypted_key) : Buffer.alloc(0);
      cek = unwrapCek(alg, enc, key, header, encryptedKey);
      matchedHeader = header;
      matchedEnc = enc;
      break;
    } catch (err) {
      lastError = err;
    }
  }

  if (cek === undefined || matchedEnc === undefined || matchedHeader === undefined) {
    if (lastError instanceof JweError) throw lastError;
    throw new JweError(ErrorCode.KEY_NOT_FOUND, 'decryptJson: no recipient could be decrypted with the supplied key.');
  }

  const plaintext = contentDecrypt(
    matchedEnc,
    cek,
    b64uDecode(/** @type {string} */ (jwe.iv)),
    b64uDecode(/** @type {string} */ (jwe.ciphertext)),
    b64uDecode(/** @type {string} */ (jwe.tag)),
    aad,
  );

  const payload = decodePlaintext(plaintext);
  enforceExpiry(payload, options);
  return { protectedHeader: matchedHeader, payload };
}

/**
 * Normalise a General or Flattened JWE into a list of recipients.
 *
 * @param {Record<string, unknown>} jwe
 * @returns {Array<{ header?: Record<string, unknown>, encrypted_key?: string }>}
 */
function normalizeRecipients(jwe) {
  if (isArray(jwe.recipients)) {
    return /** @type {Array<{ header?: Record<string, unknown>, encrypted_key?: string }>} */ (jwe.recipients);
  }
  // Flattened: the single recipient's members sit at the top level.
  return [
    {
      header: isObject(jwe.header) ? /** @type {Record<string, unknown>} */ (jwe.header) : undefined,
      encrypted_key: isString(jwe.encrypted_key) ? /** @type {string} */ (jwe.encrypted_key) : undefined,
    },
  ];
}

/**
 * @param {unknown} allowlist
 * @param {string} code
 * @param {string} label
 * @returns {string[]}
 */
function requireAllowlist(allowlist, code, label) {
  if (!isArray(allowlist) || allowlist.length === 0 || !allowlist.every(isString)) {
    throw new JweError(code, `decryptJson requires a non-empty options.${label} allowlist (string[]).`);
  }
  return /** @type {string[]} */ (allowlist);
}
