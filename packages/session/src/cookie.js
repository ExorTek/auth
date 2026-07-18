import {
  parseCookies as sharedParseCookies,
  serialiseCookie as sharedSerialiseCookie,
  serialiseDeleteCookie as sharedSerialiseDeleteCookie,
} from '@exortek/shared/cookie';

import { SessionError, ErrorCode } from './errors.js';

/**
 * @typedef {import('@exortek/shared/cookie').CookieOptions} CookieOptions
 */

/**
 * Parse a `Cookie:` request header into a name → value map. Pure
 * re-export of the shared parser — never throws.
 *
 * @param {string | null | undefined} header
 * @returns {Record<string, string>}
 */
export const parseCookies = sharedParseCookies;

/**
 * Build a `Set-Cookie` header value. Attribute violations (bad
 * SameSite, __Host- / __Secure- prefix, unsafe Domain / Path) surface
 * as {@link SessionError} `INVALID_ARGUMENT` at boot time.
 *
 * @param {string} name
 * @param {string} value
 * @param {CookieOptions} [options]
 * @returns {string}
 */
export function serialiseCookie(name, value, options) {
  try {
    return sharedSerialiseCookie(name, value, options);
  } catch (err) {
    throw new SessionError(ErrorCode.INVALID_ARGUMENT, err instanceof Error ? err.message : String(err));
  }
}

/**
 * Build a `Set-Cookie` value that instructs the browser to delete the
 * cookie.
 *
 * @param {string} name
 * @param {CookieOptions} [options]
 * @returns {string}
 */
export function serialiseDeleteCookie(name, options) {
  try {
    return sharedSerialiseDeleteCookie(name, options);
  } catch (err) {
    throw new SessionError(ErrorCode.INVALID_ARGUMENT, err instanceof Error ? err.message : String(err));
  }
}
