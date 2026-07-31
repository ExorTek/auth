/**
 * `@exortek/jwe` — JSON Web Encryption for Node.js 22+.
 *
 *   - RFC 7516 (JWE core) — compact + JSON serialisation
 *   - RFC 7518 (JWA) — RSA-OAEP / ECDH-ES / AES-KW / dir key management,
 *     AES-GCM + AES-CBC-HMAC content encryption
 *   - RFC 8725 — JWT / JWE best practices we bake in
 *
 * Server-only, zero-dep. Named exports for tree-shaking, plus a `jwe`
 * namespace that mirrors the ARCHITECTURE example. `alg` + `enc`
 * allowlists are mandatory on `decrypt`; `RSA1_5` is never accepted.
 */

import { encrypt } from './encrypt.js';
import { decrypt } from './decrypt.js';
import { decode, decodeProtectedHeader } from './decode.js';
import { encryptJson, decryptJson } from './json.js';
import { JweError, ErrorCode } from './internal/errors.js';

export { encrypt, decrypt, decode, decodeProtectedHeader };
export { encryptJson, decryptJson };
export { JweError, ErrorCode };

/**
 * Bundled namespace matching the ARCHITECTURE example.
 */
export const jwe = Object.freeze({
  encrypt,
  decrypt,
  decode,
  decodeProtectedHeader,
  encryptJson,
  decryptJson,
});

/**
 * @typedef {import('./encrypt.js').EncryptOptions} EncryptOptions
 * @typedef {import('./encrypt.js').KeyInput} KeyInput
 * @typedef {import('./decrypt.js').DecryptOptions} DecryptOptions
 * @typedef {import('./decrypt.js').DecryptResult} DecryptResult
 * @typedef {import('./decode.js').DecodedJwe} DecodedJwe
 * @typedef {import('./json.js').GeneralJwe} GeneralJwe
 */
