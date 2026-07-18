import { hmac } from '@exortek/shared/hmac';

/**
 * HMAC-SHA-256 → base64url. Used as the tag for signed CSRF tokens and any
 * other MACed value in this package.
 * @param {string | Buffer | Uint8Array} data
 * @param {string | Buffer | Uint8Array} secret
 * @returns {string}
 */
export function hmacBase64Url(data, secret) {
  return /** @type {string} */ (hmac('sha256', secret, data, 'base64url'));
}
