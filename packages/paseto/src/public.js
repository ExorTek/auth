/**
 * v4.public — high-level asymmetric (signed) tokens. The choice when a
 * relying party other than the issuer must verify the token: the payload
 * is authenticated and readable by anyone, tamper-proof via Ed25519.
 *
 *   const { secretKey, publicKey } = generateKeyPair();
 *   const token   = sign({ userId: 1 }, secretKey, { expiresIn: '1h' });
 *   const payload = verify(token, publicKey);
 */

import { signRaw, verifyRaw } from './internal/v4public.js';
import { serializePayload, serializeFooter, finalize, toBuffer } from './internal/message.js';
import { assertNonEmptyString } from './internal/guards.js';
import { assertTokenSize, DEFAULT_MAX_TOKEN_SIZE } from './internal/size.js';

/**
 * Sign a payload into a `v4.public` token.
 *
 * @param {Record<string, unknown> | string | Uint8Array} payload
 * @param {import('node:crypto').KeyObject | Uint8Array} secretKey  Ed25519 secret (32/64B or KeyObject)
 * @param {import('./local.js').EncryptOptions} [options]
 * @returns {string}
 */
export function sign(payload, secretKey, options = {}) {
  return signRaw({
    message: serializePayload(payload, options),
    secretKey,
    footer: serializeFooter(options.footer),
    implicit: toBuffer(options.assertion, 'assertion'),
  });
}

/**
 * Verify a `v4.public` token and validate its claims.
 *
 * @param {string} token
 * @param {import('node:crypto').KeyObject | Uint8Array} publicKey  Ed25519 public (32B or KeyObject)
 * @param {import('./local.js').DecryptOptions} [options]
 * @returns {Record<string, unknown> | string | { payload: unknown, footer: string, version: string, purpose: string }}
 */
export function verify(token, publicKey, options = {}) {
  assertNonEmptyString(token, 'verify.token');
  assertTokenSize(token, options.maxTokenSize ?? DEFAULT_MAX_TOKEN_SIZE);
  const { message, footer } = verifyRaw({
    token,
    publicKey,
    implicit: toBuffer(options.assertion, 'assertion'),
  });
  return finalize(message, footer, options, 'public');
}
