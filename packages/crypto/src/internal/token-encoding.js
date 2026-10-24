import { decode } from '../encode/base64url.js';
import { CryptoError } from '../errors.js';

/**
 * Decode a token this library emitted. `Buffer.from(s, 'base64url')`
 * silently skips characters outside the alphabet and ignores padding, so
 * `t + '='`, `t + '\n'`, `' ' + t` or a stray `!` mid-token all decoded to
 * the same bytes — one sealed value with endless valid spellings (a
 * problem for anything keyed on the token string: deny lists, replay
 * caches, dedupe). Only the exact unpadded canonical form is accepted.
 *
 * @param {string} token
 * @param {string} code   error code to raise for a non-canonical token
 * @returns {Buffer}
 */
export function decodeStrict(token, code) {
  if (token.includes('=')) {
    throw new CryptoError(code, 'token is not canonical unpadded base64url');
  }
  try {
    return decode(token);
  } catch (err) {
    throw new CryptoError(code, 'token is not canonical unpadded base64url', { cause: err });
  }
}
