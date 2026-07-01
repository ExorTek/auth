import crypto from 'node:crypto';
import { assertBytesOrString } from '../internal/validate.js';
import { _resolveOptions } from './hash.js';

/**
 * Compute a keyed HMAC (RFC 2104) over `data`.
 *
 * HMAC provides both integrity and authenticity — an attacker who does not
 * know `secret` cannot forge a valid MAC. Suitable for signed cookies,
 * webhook signatures, cache keys derived from user input, and any
 * "prove-you-know-the-key" scenario.
 *
 * The default algorithm is `sha256`; use `options.algo` to select another.
 *
 * **Security warning:** never accept `md5` or `sha1` for MAC verification
 * of untrusted input — while HMAC is more resilient than the underlying
 * hash, prefer `sha256`+ for anything security-sensitive.
 *
 * @param {string | Buffer | Uint8Array} data
 * @param {string | Buffer | Uint8Array} secret  Key material.
 * @param {import('./hash.js').HashOptions} [options]
 * @returns {string}     Encoded MAC (hex by default).
 * @throws {CryptoError} With code `INVALID_ARGUMENT` if `data` or `secret` is invalid,
 *                       or `UNSUPPORTED_ALGORITHM` if `options.algo` is not recognised.
 *
 * @example
 * hmac('userid:42', process.env.SESSION_SECRET)   // sha256 hex
 * hmac(payload, key, { algo: 'sha512' })          // sha512 hex
 */
export function hmac(data, secret, options) {
  assertBytesOrString(data, 'data');
  assertBytesOrString(secret, 'secret');
  const { algo, encoding } = _resolveOptions(options);
  return crypto.createHmac(algo, secret).update(data).digest(encoding);
}
