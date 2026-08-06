/**
 * Origin comparison for `clientData.origin`.
 *
 * `expectedOrigin` accepts three shapes:
 *   - a single string          → exact equality
 *   - a string[]               → any-of
 *   - a RegExp                 → tested against `actual`
 *
 * String comparison is exact — we do NOT normalise scheme, host
 * case, or trailing slashes. A trailing slash on origin would
 * violate WHATWG URL and no browser produces it; case differences
 * in scheme or host don't occur in practice either. Native app
 * origins (`android:apk-key-hash:*`, `ios:bundle-id:*`) are opaque
 * strings — no URL parsing on those.
 */

import { PasskeyError, ErrorCode } from '../errors.js';

/**
 * @param {string} actual
 * @param {string | string[] | RegExp} expected
 * @returns {boolean}
 */
export function matchesOrigin(actual, expected) {
  if (typeof actual !== 'string') {
    throw new PasskeyError(ErrorCode.INVALID_ARGUMENT, 'originCheck: actual must be a string');
  }
  if (typeof expected === 'string') {
    return actual === expected;
  }
  if (Array.isArray(expected)) {
    for (const candidate of expected) {
      if (typeof candidate !== 'string') {
        throw new PasskeyError(ErrorCode.INVALID_ARGUMENT, 'originCheck: expected[] entries must all be strings');
      }
      if (actual === candidate) {
        return true;
      }
    }
    return false;
  }
  if (expected instanceof RegExp) {
    // `.test()` on a global/sticky RegExp advances `lastIndex`, so a
    // caller who passes `/…/g` would get alternating results across
    // ceremonies — an intermittent origin bypass/lockout. Test against
    // a flag-stripped clone so matching is always stateless.
    const stateless =
      expected.global || expected.sticky ? new RegExp(expected.source, expected.flags.replace(/[gy]/g, '')) : expected;
    return stateless.test(actual);
  }
  throw new PasskeyError(ErrorCode.INVALID_ARGUMENT, 'originCheck: expected must be string, string[], or RegExp');
}
