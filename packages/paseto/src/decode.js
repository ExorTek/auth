/**
 * **UNVERIFIED** PASETO inspection — reads a token's version, purpose,
 * and footer **without any key and without authenticating anything**.
 *
 * The footer is PASETO's out-of-band metadata channel (§Payload
 * Processing): it is authenticated by the MAC / signature but readable
 * before verification, which is exactly what you need to pick a key by
 * `kid` before calling `decrypt` / `verify`.
 *
 * Never gate authorisation on this. The payload is deliberately not
 * returned — for `v4.local` it is encrypted, and for `v4.public` it is
 * unverified, so acting on it would defeat the point.
 */

import { isString } from '@exortek/shared/predicates';

import * as b64 from './internal/base64url.js';
import { assertTokenSize, DEFAULT_MAX_TOKEN_SIZE } from './internal/size.js';
import { PasetoError, ErrorCode } from './internal/errors.js';

/**
 * @typedef {Object} DecodedPaseto
 * @property {string} version                         'v4'
 * @property {string} purpose                         'local' | 'public'
 * @property {Record<string, unknown> | string | undefined} footer
 *   The decoded footer — a parsed object when it is JSON, the raw string
 *   otherwise, or `undefined` when the token carries no footer.
 */

/**
 * Read `{ version, purpose, footer }` from a token without verifying it.
 *
 * @param {string} token
 * @param {{ maxTokenSize?: number }} [options]
 * @returns {DecodedPaseto}
 */
export function decode(token, options = {}) {
  if (!isString(token) || token.length === 0) {
    throw new PasetoError(ErrorCode.INVALID_TOKEN, 'decode: expected a non-empty string token');
  }
  assertTokenSize(token, options.maxTokenSize ?? DEFAULT_MAX_TOKEN_SIZE);

  const parts = token.split('.');
  if (parts.length < 3 || parts.length > 4) {
    throw new PasetoError(ErrorCode.INVALID_TOKEN, 'decode: not a compact PASETO token');
  }
  const [version, purpose] = parts;
  if (version !== 'v4' || (purpose !== 'local' && purpose !== 'public')) {
    throw new PasetoError(ErrorCode.INVALID_TOKEN, `decode: unsupported version/purpose '${version}.${purpose}'`);
  }

  let footer;
  if (parts.length === 4 && parts[3]) {
    const text = b64.decode(parts[3]).toString('utf8');
    const trimmed = text.trimStart();
    if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
      try {
        footer = JSON.parse(text);
      } catch {
        footer = text;
      }
    } else {
      footer = text;
    }
  }

  return { version, purpose, footer };
}
