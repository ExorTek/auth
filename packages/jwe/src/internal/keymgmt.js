/**
 * Key management — the JWE `alg` step. Produces the Content Encryption
 * Key (CEK) and the JWE Encrypted Key segment on encrypt, and recovers
 * the CEK on decrypt, dispatching on the algorithm family:
 *
 *   - `dir`     (§4.5) — the caller's symmetric key *is* the CEK; no wrap.
 *   - AES-KW    (§4.4) — random CEK wrapped under the KEK via RFC 3394.
 *   - RSA-OAEP  (§4.3) — random CEK wrapped with the recipient's RSA key.
 *   - ECDH-ES   (§4.6) — ephemeral-static ECDH + Concat KDF; either the
 *     derived key is the CEK (`ECDH-ES`) or it is a KEK that wraps a
 *     random CEK (`ECDH-ES+A*KW`). The ephemeral public key travels in
 *     the protected header as `epk`.
 */

import {
  randomBytes,
  generateKeyPairSync,
  diffieHellman,
  publicEncrypt,
  privateDecrypt,
  createPublicKey,
  constants,
} from 'node:crypto';
import { isObject } from '@exortek/shared/predicates';
import { aesKeyWrap, aesKeyUnwrap } from './keywrap.js';
import { concatKdf } from './concatkdf.js';
import { normalizeSymmetric, normalizePublicKey, normalizePrivateKey, assertRsaPublicKey } from './keys.js';
import { encode as b64uEncode, decode as b64uDecode } from './base64url.js';
import { JweError, ErrorCode } from './errors.js';

/** @typedef {import('./algorithms.js').KeyManagementDescriptor} AlgDescriptor */
/** @typedef {import('./encryptions.js').ContentEncryptionDescriptor} EncDescriptor */
/** @typedef {import('./keys.js').KeyInput} KeyInput */

/** JOSE curve name → OpenSSL named curve. */
const EC_CURVES = { 'P-256': 'prime256v1', 'P-384': 'secp384r1', 'P-521': 'secp521r1' };

/**
 * Coerce an optional `apu` / `apv` input into a byte buffer.
 *
 * @param {unknown} value
 * @returns {Buffer}
 */
function optionalBytes(value) {
  if (value === undefined || value === null) {
    return Buffer.alloc(0);
  }
  if (Buffer.isBuffer(value)) {
    return value;
  }
  if (value instanceof Uint8Array) {
    return Buffer.from(value);
  }
  if (typeof value === 'string') {
    return Buffer.from(value, 'utf8');
  }
  throw new JweError(ErrorCode.INVALID_ARGUMENT, 'apu / apv must be a string, Buffer, or Uint8Array.');
}

/**
 * The wrap output: the CEK plus the Encrypted Key segment and any
 * header parameters the key-management step contributes (e.g. `epk`).
 *
 * @typedef {Object} WrapResult
 * @property {Buffer} cek
 * @property {Buffer} encryptedKey
 * @property {Record<string, unknown>} header
 */

/**
 * Derive the CEK and Encrypted Key for one recipient.
 *
 * @param {AlgDescriptor} alg
 * @param {EncDescriptor} enc
 * @param {KeyInput} key
 * @param {{ apu?: unknown, apv?: unknown }} [options]
 * @param {Buffer} [sharedCek]  A CEK fixed by the caller (JSON multi-recipient).
 *   Not permitted for `dir` / bare `ECDH-ES`, which determine the CEK themselves.
 * @returns {WrapResult}
 */
export function wrapCek(alg, enc, key, options = {}, sharedCek) {
  switch (alg.kind) {
    case 'dir': {
      if (sharedCek) {
        throw sharedCekUnsupported(alg.alg);
      }
      return { cek: normalizeSymmetric(key, enc.cekBytes, alg.alg), encryptedKey: EMPTY, header: {} };
    }
    case 'aeskw': {
      const kek = normalizeSymmetric(key, /** @type {number} */ (alg.bits) / 8, alg.alg);
      const cek = sharedCek ?? randomBytes(enc.cekBytes);
      return { cek, encryptedKey: aesKeyWrap(kek, cek), header: {} };
    }
    case 'rsa': {
      const publicKey = normalizePublicKey(key);
      assertRsaPublicKey(publicKey);
      const cek = sharedCek ?? randomBytes(enc.cekBytes);
      const encryptedKey = publicEncrypt(
        { key: publicKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: alg.hash },
        cek,
      );
      return { cek, encryptedKey, header: {} };
    }
    case 'ecdh': {
      const recipient = normalizePublicKey(key);
      const apu = optionalBytes(options.apu);
      const apv = optionalBytes(options.apv);
      const { z, epk } = ecdhAgreeSender(recipient);
      const header = /** @type {Record<string, unknown>} */ ({ epk });
      if (apu.length) {
        header.apu = b64uEncode(apu);
      }
      if (apv.length) {
        header.apv = b64uEncode(apv);
      }

      if (alg.wrap === null) {
        if (sharedCek) {
          throw sharedCekUnsupported(alg.alg);
        }
        const cek = concatKdf(z, enc.cekBytes * 8, enc.enc, apu, apv);
        return { cek, encryptedKey: EMPTY, header };
      }
      const wrapBits = alg.wrap === 'A128KW' ? 128 : 256;
      const kek = concatKdf(z, wrapBits, alg.alg, apu, apv);
      const cek = sharedCek ?? randomBytes(enc.cekBytes);
      return { cek, encryptedKey: aesKeyWrap(kek, cek), header };
    }
    /* c8 ignore next 2 */
    default:
      throw new JweError(ErrorCode.UNSUPPORTED_ALGORITHM, `unhandled key-management kind for ${alg.alg}.`);
  }
}

/**
 * Recover the CEK for one recipient.
 *
 * @param {AlgDescriptor} alg
 * @param {EncDescriptor} enc
 * @param {KeyInput} key
 * @param {Record<string, unknown>} header  The merged (protected + per-recipient) header.
 * @param {Buffer} encryptedKey
 * @returns {Buffer}
 */
export function unwrapCek(alg, enc, key, header, encryptedKey) {
  switch (alg.kind) {
    case 'dir': {
      if (encryptedKey.length) {
        throw new JweError(ErrorCode.DECRYPTION_FAILED, 'dir: the Encrypted Key segment must be empty.');
      }
      return normalizeSymmetric(key, enc.cekBytes, alg.alg);
    }
    case 'aeskw': {
      const kek = normalizeSymmetric(key, /** @type {number} */ (alg.bits) / 8, alg.alg);
      return assertCekLength(aesKeyUnwrap(kek, encryptedKey), enc);
    }
    case 'rsa': {
      const privateKey = normalizePrivateKey(key);
      let cek;
      try {
        cek = privateDecrypt(
          { key: privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: alg.hash },
          encryptedKey,
        );
      } catch (err) {
        throw new JweError(
          ErrorCode.DECRYPTION_FAILED,
          'RSA-OAEP unwrap failed — wrong key or corrupted encrypted key.',
          {
            cause: err,
          },
        );
      }
      return assertCekLength(cek, enc);
    }
    case 'ecdh': {
      const privateKey = normalizePrivateKey(key);
      const z = ecdhAgreeRecipient(privateKey, header.epk);
      const apu = header.apu === undefined ? Buffer.alloc(0) : b64uDecode(/** @type {string} */ (header.apu));
      const apv = header.apv === undefined ? Buffer.alloc(0) : b64uDecode(/** @type {string} */ (header.apv));

      if (alg.wrap === null) {
        return concatKdf(z, enc.cekBytes * 8, enc.enc, apu, apv);
      }
      const wrapBits = alg.wrap === 'A128KW' ? 128 : 256;
      const kek = concatKdf(z, wrapBits, alg.alg, apu, apv);
      return assertCekLength(aesKeyUnwrap(kek, encryptedKey), enc);
    }
    /* c8 ignore next 2 */
    default:
      throw new JweError(ErrorCode.UNSUPPORTED_ALGORITHM, `unhandled key-management kind for ${alg.alg}.`);
  }
}

const EMPTY = Buffer.alloc(0);

/**
 * @param {string} alg
 * @returns {JweError}
 */
function sharedCekUnsupported(alg) {
  return new JweError(
    ErrorCode.INVALID_ARGUMENT,
    `${alg} determines the content-encryption key itself and cannot share a CEK with other recipients — use it as the sole recipient.`,
  );
}

/**
 * @param {Buffer} cek
 * @param {EncDescriptor} enc
 * @returns {Buffer}
 */
function assertCekLength(cek, enc) {
  if (cek.length !== enc.cekBytes) {
    throw new JweError(
      ErrorCode.DECRYPTION_FAILED,
      `recovered CEK is ${cek.length} bytes, expected ${enc.cekBytes} for ${enc.enc}.`,
    );
  }
  return cek;
}

/**
 * Sender side of ECDH-ES: generate an ephemeral key on the recipient's
 * curve and compute the shared secret Z. Returns Z and the ephemeral
 * public key as a JWK for the `epk` header.
 *
 * @param {import('node:crypto').KeyObject} recipient
 * @returns {{ z: Buffer, epk: Record<string, unknown> }}
 */
function ecdhAgreeSender(recipient) {
  const jwk = /** @type {Record<string, string>} */ (recipient.export({ format: 'jwk' }));
  let ephemeral;
  if (jwk.kty === 'EC' && EC_CURVES[/** @type {keyof typeof EC_CURVES} */ (jwk.crv)]) {
    ephemeral = generateKeyPairSync('ec', { namedCurve: EC_CURVES[/** @type {keyof typeof EC_CURVES} */ (jwk.crv)] });
  } else if (jwk.kty === 'OKP' && jwk.crv === 'X25519') {
    ephemeral = generateKeyPairSync('x25519');
  } else {
    throw new JweError(
      ErrorCode.INVALID_KEY,
      `ECDH-ES needs an EC (P-256/384/521) or X25519 recipient key, got ${jwk.kty}/${jwk.crv}.`,
    );
  }
  const z = diffieHellman({ privateKey: ephemeral.privateKey, publicKey: recipient });
  return { z, epk: /** @type {Record<string, unknown>} */ (ephemeral.publicKey.export({ format: 'jwk' })) };
}

/**
 * Recipient side of ECDH-ES: rebuild the ephemeral public key from `epk`
 * and compute the shared secret Z with the recipient's private key.
 *
 * @param {import('node:crypto').KeyObject} privateKey
 * @param {unknown} epk
 * @returns {Buffer}
 */
function ecdhAgreeRecipient(privateKey, epk) {
  if (!isObject(epk)) {
    throw new JweError(
      ErrorCode.INVALID_HEADER,
      'ECDH-ES: protected header is missing a valid "epk" (ephemeral public key).',
    );
  }
  let ephemeralPublic;
  try {
    ephemeralPublic = createPublicKey({ key: /** @type {import('node:crypto').JsonWebKey} */ (epk), format: 'jwk' });
  } catch (err) {
    throw new JweError(
      ErrorCode.INVALID_HEADER,
      `ECDH-ES: "epk" is not a valid public key — ${err instanceof Error ? err.message : String(err)}`,
      {
        cause: err,
      },
    );
  }
  try {
    return diffieHellman({ privateKey, publicKey: ephemeralPublic });
  } catch (err) {
    throw new JweError(
      ErrorCode.DECRYPTION_FAILED,
      'ECDH-ES key agreement failed — the "epk" curve does not match the recipient key.',
      {
        cause: err,
      },
    );
  }
}
