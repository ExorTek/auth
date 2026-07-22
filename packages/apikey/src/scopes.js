/**
 * Scope match helpers.
 *
 * A **granted** scope authorises access. A **required** scope names the
 * access an endpoint needs. `hasAll` / `hasAny` decide whether the
 * granted set covers the requirement, with wildcard support:
 *
 * - `'*'` in the granted list → matches every required scope.
 * - A `'ns:*'` suffix wildcard → matches any scope under the namespace
 *   (`'read:*'` covers `'read:users'` and `'read:posts'`).
 * - Exact string match otherwise.
 *
 * Wildcards apply only on the granted side. `required` values must be
 * concrete — an API cannot demand "some read:* scope"; it must state
 * exactly which one it needs.
 */

import { isArray, isString } from '@exortek/shared/predicates';

/**
 * Does `granted` cover a single `required` scope?
 * @param {string[]} granted
 * @param {string} required
 * @returns {boolean}
 */
export function covers(granted, required) {
  if (!isArray(granted) || !isString(required) || required.length === 0) {
    return false;
  }
  for (const g of granted) {
    if (!isString(g)) {
      continue;
    }
    if (g === '*' || g === required) {
      return true;
    }
    // Suffix wildcard: `read:*` matches `read:users`.
    if (g.endsWith(':*')) {
      const ns = g.slice(0, -1); // 'read:'
      if (required.startsWith(ns) && required.length > ns.length) {
        return true;
      }
    }
  }
  return false;
}

/**
 * All required scopes must be covered by granted.
 * @param {string[]} granted
 * @param {string[]} required
 * @returns {boolean}
 */
export function hasAll(granted, required) {
  if (!isArray(required)) {
    return false;
  }
  if (required.length === 0) {
    return true;
  }
  for (const r of required) {
    if (!covers(granted, r)) {
      return false;
    }
  }
  return true;
}

/**
 * At least one required scope must be covered.
 * @param {string[]} granted
 * @param {string[]} required
 * @returns {boolean}
 */
export function hasAny(granted, required) {
  if (!isArray(required) || required.length === 0) {
    return false;
  }
  for (const r of required) {
    if (covers(granted, r)) {
      return true;
    }
  }
  return false;
}
