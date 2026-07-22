import { seal, unseal, CryptoError, ErrorCode as CryptoErrorCode } from '@exortek/crypto';
import { isArray, isBytes, isFunction, isString } from '@exortek/shared/predicates';

import { assertNonEmptyString, assertObject, invalidArgument } from './internal/guards.js';
import { parseCookies, serialiseCookie, serialiseDeleteCookie } from './cookie.js';
import { parseDuration } from './internal/duration.js';

/**
 * "Trusted device" cookie — long-lived, opaque, HMAC-authenticated
 * cookie separate from the session cookie. The classic use case is the
 * 2FA "remember this device for 30 days" tick-box: on subsequent logins
 * the caller can skip the TOTP prompt when this cookie is present and
 * valid.
 *
 * Deliberately kept independent from `createSessionManager` — the two
 * live at different scopes (the session cookie is per-session, the
 * trusted-device cookie is per-user across many sessions), so they
 * don't share config or a store.
 *
 * @param {{
 *   secret:   string | Buffer | Uint8Array | Array<string | Buffer | Uint8Array>,
 *   ttl:      string | number,           // e.g. '30d'
 *   cookie?:  Omit<import('./cookie.js').CookieOptions, 'maxAge' | 'expires'> & { name?: string },
 * }} config
 */
export function createTrustedDeviceCookie(config) {
  assertObject(config, 'createTrustedDeviceCookie.config');
  const secret = isArray(config.secret) ? config.secret : [config.secret];
  if (secret.length === 0 || secret.some(s => !isString(s) && !isBytes(s))) {
    throw invalidArgument(
      'createTrustedDeviceCookie.config.secret must be a non-empty string / Buffer / Uint8Array (or an array of those)',
    );
  }
  const ttlMs = parseDuration(config.ttl, 'ttl');
  const cookieName = config.cookie?.name ?? '__Host-td';
  const cookieOptions = { ...config.cookie };
  delete cookieOptions.name;

  return {
    /**
     * Mint a trusted-device cookie for a user. Call this at 2FA completion
     * when the user ticked "remember me on this device".
     *
     * `extraClaims` keys named `uid`, `iat`, or `exp` are ignored — the
     * reserved fields always win.
     *
     * @param {string} userId
     * @param {{ now?: number, extraClaims?: object }} [options]
     * @returns {string}   Set-Cookie header value.
     */
    issue(userId, options = {}) {
      assertNonEmptyString(userId, 'trustedDevice.issue.userId');
      const now = options.now ?? Date.now();
      // Reserved fields are written AFTER the extraClaims spread so a
      // caller-supplied (possibly user-influenced) claims object can
      // never clobber uid/iat/exp — extraClaims.uid overriding the
      // userId argument would let one user's cookie verify as another's.
      const payload = {
        ...(options.extraClaims ?? {}),
        uid: userId,
        iat: now,
        exp: now + ttlMs,
      };
      const token = seal(payload, secret[0], { ttl: Math.max(1, Math.ceil(ttlMs / 1000)), now });
      return serialiseCookie(cookieName, token, {
        ...cookieOptions,
        maxAge: Math.floor(ttlMs / 1000),
      });
    },

    /**
     * Check whether the incoming request carries a trusted-device
     * cookie belonging to `userId`. Returns `true` on a valid,
     * unexpired, correctly-scoped cookie; `false` otherwise. Never
     * throws.
     *
     * @param {any} req
     * @param {string} userId
     * @param {{ now?: number }} [options]
     * @returns {boolean}
     */
    verify(req, userId, options = {}) {
      if (typeof userId !== 'string' || userId.length === 0) {
        return false;
      }
      const headers = req?.headers;
      if (!headers) {
        return false;
      }
      const cookieHeader = isFunction(headers.get) ? headers.get('cookie') : (headers.cookie ?? headers.Cookie);
      if (!cookieHeader) {
        return false;
      }
      const token = parseCookies(cookieHeader)[cookieName];
      if (!token) {
        return false;
      }
      const now = options.now ?? Date.now();
      try {
        const { payload } = unseal(token, secret, { now });
        return payload && payload.uid === userId;
      } catch (err) {
        if (err instanceof CryptoError && err.code === CryptoErrorCode.TOKEN_EXPIRED) {
          return false;
        }
        return false;
      }
    },

    /**
     * Produce a delete-cookie header value — call this on explicit
     * logout / "forget this device" flows.
     * @returns {string}
     */
    revoke() {
      return serialiseDeleteCookie(cookieName, cookieOptions);
    },

    get cookieName() {
      return cookieName;
    },
  };
}
