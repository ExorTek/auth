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
import { resolveKey } from './key.js';

/**
 * Sign a payload into a `v4.public` token.
 *
 * @param {Record<string, unknown> | string | Uint8Array} payload
 * @param {import('./key.js').PasetoKey} secretKey  a v4 `secret` key
 * @param {import('./local.js').EncryptOptions} [options]
 * @returns {string}
 */
export function sign(payload, secretKey, options = {}) {
  const sk = resolveKey(secretKey, 'secret', 'sign');
  return signRaw({
    message: serializePayload(payload, options),
    secretKey: sk,
    footer: serializeFooter(options.footer),
    implicit: toBuffer(options.assertion, 'assertion'),
  });
}

/**
 * Verify a `v4.public` token and validate its claims.
 *
 * @param {string} token
 * @param {import('./key.js').PasetoKey} publicKey  a v4 `public` key
 * @param {import('./local.js').DecryptOptions} [options]
 * @returns {Record<string, unknown> | string | { payload: unknown, footer: string, version: string, purpose: string }}
 */
export function verify(token, publicKey, options = {}) {
  const pk = resolveKey(publicKey, 'public', 'verify');
  assertNonEmptyString(token, 'verify.token');
  assertTokenSize(token, options.maxTokenSize ?? DEFAULT_MAX_TOKEN_SIZE);
  const { message, footer } = verifyRaw({
    token,
    publicKey: pk,
    implicit: toBuffer(options.assertion, 'assertion'),
  });
  return finalize(message, footer, options, 'public');
}
