/**
 * v4.local — high-level symmetric (encrypted) tokens. The recommended
 * choice for tokens your own services both mint and read: the payload is
 * confidential, not just authenticated.
 *
 *   const key = generateKey();
 *   const token = encrypt({ userId: 1 }, key, { expiresIn: '1h' });
 *   const data  = decrypt(token, key);
 */

import { encryptRaw, decryptRaw } from './internal/v4local.js';
import { serializePayload, serializeFooter, finalize, toBuffer } from './internal/message.js';
import { assertNonEmptyString } from './internal/guards.js';
import { assertTokenSize, DEFAULT_MAX_TOKEN_SIZE } from './internal/size.js';

/**
 * @typedef {import('./internal/claims.js')} _claims
 * @typedef {Object} EncryptOptions
 * @property {string | number} [expiresIn]     duration → `exp`
 * @property {string | number} [notBefore]     duration → `nbf`
 * @property {boolean} [iat=true]              stamp `iat`
 * @property {string} [issuer]                 → `iss`
 * @property {string} [subject]                → `sub`
 * @property {string} [audience]               → `aud`
 * @property {string} [jti]                    → `jti`
 * @property {Record<string, unknown> | string} [footer]   authenticated, not encrypted
 * @property {string | Uint8Array} [assertion]  implicit assertion (bound, not stored)
 *
 * @typedef {Object} DecryptOptions
 * @property {string | number} [clockTolerance=0]
 * @property {boolean} [ignoreExp=false]
 * @property {boolean} [ignoreNbf=false]
 * @property {string} [issuer]                 required `iss`
 * @property {string} [subject]                required `sub`
 * @property {string} [audience]               required `aud`
 * @property {string | Uint8Array} [assertion]
 * @property {number} [maxTokenSize=8192]      reject larger tokens with `TOKEN_TOO_LARGE`
 * @property {boolean} [complete=false]        return `{ payload, footer, version, purpose }`
 */

/**
 * Encrypt a payload into a `v4.local` token.
 *
 * @param {Record<string, unknown> | string | Uint8Array} payload
 * @param {Uint8Array} key   32-byte symmetric key
 * @param {EncryptOptions} [options]
 * @returns {string}
 */
export function encrypt(payload, key, options = {}) {
  return encryptRaw({
    message: serializePayload(payload, options),
    key,
    footer: serializeFooter(options.footer),
    implicit: toBuffer(options.assertion, 'assertion'),
  });
}

/**
 * Decrypt and validate a `v4.local` token.
 *
 * @param {string} token
 * @param {Uint8Array} key
 * @param {DecryptOptions} [options]
 * @returns {Record<string, unknown> | string | { payload: unknown, footer: string, version: string, purpose: string }}
 */
export function decrypt(token, key, options = {}) {
  assertNonEmptyString(token, 'decrypt.token');
  assertTokenSize(token, options.maxTokenSize ?? DEFAULT_MAX_TOKEN_SIZE);
  const { message, footer } = decryptRaw({
    token,
    key,
    implicit: toBuffer(options.assertion, 'assertion'),
  });
  return finalize(message, footer, options, 'local');
}
