/**
 * UserInfo claim selection (OpenID Connect Core §5.3 / §5.4).
 *
 * Which claims a UserInfo response may carry is the intersection of three
 * things: the scopes the access token was granted (each standard scope maps
 * to a fixed claim set, §5.4), the provider's `claims.userinfo` allow-list
 * (when configured), and the claims the backing store actually holds for the
 * subject. `sub` is always present (§5.3.2).
 */

// OIDC Core §5.4 — the claims each standard scope releases.
export const SCOPE_CLAIMS = Object.freeze({
  profile: [
    'name',
    'family_name',
    'given_name',
    'middle_name',
    'nickname',
    'preferred_username',
    'profile',
    'picture',
    'website',
    'gender',
    'birthdate',
    'zoneinfo',
    'locale',
    'updated_at',
  ],
  email: ['email', 'email_verified'],
  address: ['address'],
  phone: ['phone_number', 'phone_number_verified'],
});

/**
 * Resolve the set of claim names releasable for a granted scope list.
 *
 * @param {string[]} grantedScopes
 * @param {string[]} [allowList]  optional `claims.userinfo` policy narrowing
 * @returns {Set<string>}
 */
export function releasableClaims(grantedScopes, allowList) {
  const names = new Set();
  for (const scope of grantedScopes) {
    const claims = SCOPE_CLAIMS[scope];
    if (claims) {
      for (const name of claims) {
        names.add(name);
      }
    }
  }
  if (Array.isArray(allowList)) {
    for (const name of [...names]) {
      if (!allowList.includes(name)) {
        names.delete(name);
      }
    }
  }
  return names;
}

/**
 * Build the UserInfo response body: `sub` plus every releasable claim the
 * store holds a value for.
 *
 * @param {string} sub
 * @param {Record<string, unknown>} storedClaims  every claim held for the subject
 * @param {string[]} grantedScopes
 * @param {string[]} [allowList]  optional `claims.userinfo` policy
 * @returns {Record<string, unknown>}
 */
export function buildUserInfo(sub, storedClaims, grantedScopes, allowList) {
  const releasable = releasableClaims(grantedScopes, allowList);
  /** @type {Record<string, unknown>} */
  const out = { sub };
  for (const name of releasable) {
    if (storedClaims && Object.hasOwn(storedClaims, name) && storedClaims[name] !== undefined) {
      out[name] = storedClaims[name];
    }
  }
  return out;
}
