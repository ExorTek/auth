/**
 * Token size guard. A decoder should reject an over-large token before
 * doing any base64 / crypto work — an attacker-controlled megabyte of
 * base64 is a cheap way to burn CPU. PASETO tokens are small; the
 * default ceiling is generous but bounded.
 */

import { PasetoError, ErrorCode } from './errors.js';

/** Default maximum accepted token length, in bytes. */
export const DEFAULT_MAX_TOKEN_SIZE = 8192;

/**
 * Throw `TOKEN_TOO_LARGE` when `token` exceeds `max` bytes. Pass
 * `max = 0` (or a falsy value the caller resolves) only if you have
 * already bounded the input elsewhere.
 *
 * @param {string} token
 * @param {number} [max=DEFAULT_MAX_TOKEN_SIZE]
 */
export function assertTokenSize(token, max = DEFAULT_MAX_TOKEN_SIZE) {
  const bytes = Buffer.byteLength(token, 'utf8');
  if (bytes > max) {
    throw new PasetoError(ErrorCode.TOKEN_TOO_LARGE, `token is ${bytes} bytes, exceeds maxTokenSize=${max}`);
  }
}
