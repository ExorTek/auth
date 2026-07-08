import { createHmac } from 'node:crypto';
import { encodeBase64Url } from './base64url.js';

/**
 * HMAC-SHA-256 → base64url. Used as the tag for signed CSRF tokens and any
 * other MACed value in this package.
 * @param {string | Buffer | Uint8Array} data
 * @param {string | Buffer | Uint8Array} secret
 * @returns {string}
 */
export function hmacBase64Url(data, secret) {
  const h = createHmac('sha256', secret);
  h.update(typeof data === 'string' ? data : Buffer.from(data.buffer, data.byteOffset, data.byteLength));
  return encodeBase64Url(h.digest());
}
