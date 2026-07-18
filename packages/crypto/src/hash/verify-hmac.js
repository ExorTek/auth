import crypto from 'node:crypto';
import { assertBytesOrString, assertEncoding, assertOptionalObject } from '@exortek/shared/asserts';
import { toBuffer, toBufferWithEncoding } from '../internal/bytes.js';
import { _resolveOptions } from './hash.js';

/**
 * One-shot HMAC verification — compute the HMAC of `data` under `secret`
 * and compare it timing-safely to `expected`. Returns a boolean.
 *
 * The convenience helper for webhook signature verification (Stripe,
 * GitHub, Slack, Twilio, Vercel — all use the same "HMAC-SHA256 the body,
 * ship the hex digest in a header" scheme). Replaces the two-line
 * `hmac(...) + compare(...)` idiom with a single call and closes off the
 * classic pitfall of using `===` on the comparison.
 *
 * `expected` is decoded per `options.encoding` (default `'hex'`) — pass a
 * Buffer if the signature is already bytes.
 *
 * @param {string | Buffer | Uint8Array} data      Raw payload that was signed.
 * @param {string | Buffer | Uint8Array} expected  Signature to check against.
 * @param {string | Buffer | Uint8Array} secret    HMAC key.
 * @param {import('./hash.js').HashOptions} [options]  `algo` (default sha256),
 *                                                     `encoding` for interpreting
 *                                                     a string `expected` (default 'hex').
 * @returns {boolean}
 * @throws {CryptoError} `INVALID_ARGUMENT` on invalid input types;
 *                       `UNSUPPORTED_ALGORITHM` if `options.algo` is unknown.
 *
 * @example
 * // Express webhook handler:
 * app.post('/webhook', (req, res) => {
 *   const sig = req.headers['x-signature']
 *   if (!verifyHmac(req.rawBody, sig, process.env.WEBHOOK_SECRET)) {
 *     return res.status(401).end()
 *   }
 *   // ... process event ...
 * })
 */
export function verifyHmac(data, expected, secret, options) {
  assertBytesOrString(data, 'data');
  assertBytesOrString(secret, 'secret');
  assertOptionalObject(options, 'options');
  const { algo } = _resolveOptions(options);

  const expectedBuf = _toExpectedBuffer(expected, options);
  const actualBuf = crypto.createHmac(algo, secret).update(toBuffer(data, 'data')).digest();

  if (expectedBuf.length !== actualBuf.length) {
    return false;
  }
  return crypto.timingSafeEqual(expectedBuf, actualBuf);
}

/**
 * @private
 * @param {unknown} value
 * @param {import('./hash.js').HashOptions} [options]
 */
function _toExpectedBuffer(value, options) {
  const encoding = options?.encoding ?? 'hex';
  if (typeof value === 'string') {
    assertEncoding(encoding, 'options.encoding', { allowBuffer: false });
  }
  return toBufferWithEncoding(value, 'expected', encoding);
}
