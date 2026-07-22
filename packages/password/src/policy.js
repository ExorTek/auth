import { isArray, isNumber, isString } from '@exortek/shared/predicates';

import { PasswordError, ErrorCode } from './errors.js';
import { strength } from './strength.js';

/**
 * @typedef {'too-short' | 'too-long' | 'missing-class' | 'contains-user-info' | 'in-deny-list' | 'below-min-strength'} PolicyViolation
 */

/**
 * @typedef {object} PolicyResult
 * @property {boolean} valid
 * @property {PolicyViolation[]} violations   Empty when `valid === true`.
 * @property {import('./strength.js').StrengthResult} [strength]
 *   Present only when `requireMinScore` was set, so callers avoid the
 *   entropy calc when they don't need it.
 */

/**
 * @typedef {object} PolicyRules
 * @property {number} [minLength=12]
 *   Character count after Unicode normalization. NIST SP 800-63B floor
 *   is 8; OWASP prefers 12 for interactive users.
 * @property {number} [maxLength=1024]
 *   Absolute upper bound. See `normalize.js` — memory-hard KDFs turn
 *   huge passwords into DoS surfaces.
 * @property {Array<'lower' | 'upper' | 'digit' | 'symbol'>} [requireClasses]
 *   Character classes the password MUST contain at least one of.
 *   Prefer just leaning on `requireMinScore` — NIST-2020 explicitly
 *   discourages composition rules because they reduce entropy in
 *   practice — but some regulations still require them.
 * @property {string[]} [denyList]
 *   Additional strings that MUST NOT appear in the password
 *   (case-insensitive substring match). Great for company-specific
 *   banned words on top of the built-in common-password list.
 * @property {string[]} [userInfo]
 *   Substrings — typically email, username, first name — that must not
 *   appear in the password. Case-insensitive, min length 3.
 * @property {0 | 1 | 2 | 3 | 4} [requireMinScore]
 *   If set, the password must score at least this on the coarse
 *   strength meter (0-4). Absent → skip the entropy calc.
 */

/**
 * Validate a candidate password against a set of policy rules. Returns
 * a structured result rather than throwing — callers usually want to
 * render each violation as a form-field error message.
 *
 * @example
 * const result = password.policy(input, {
 *   minLength: 12,
 *   requireClasses: ['lower', 'upper', 'digit'],
 *   denyList: [companyName, product],
 *   userInfo: [user.email, user.firstName],
 *   requireMinScore: 3,
 * })
 * if (!result.valid) return badRequest(result.violations)
 *
 * @param {unknown} password
 * @param {PolicyRules} [rules]
 * @returns {PolicyResult}
 */
export function policy(password, rules = {}) {
  if (typeof password !== 'string') {
    return { valid: false, violations: ['too-short'] };
  }
  const normalized = password.normalize('NFKC');
  const violations = [];
  const minLength = rules.minLength ?? 12;
  const maxLength = rules.maxLength ?? 1024;

  if (normalized.length < minLength) {
    violations.push('too-short');
  }
  if (normalized.length > maxLength) {
    violations.push('too-long');
  }

  if (isArray(rules.requireClasses) && rules.requireClasses.length > 0) {
    const classChecks = {
      lower: /[a-z]/,
      upper: /[A-Z]/,
      digit: /[0-9]/,
      symbol: /[!-/:-@[-`{-~]/,
    };
    for (const cls of rules.requireClasses) {
      const re = classChecks[cls];
      if (!re || !re.test(normalized)) {
        violations.push('missing-class');
        break;
      }
    }
  }

  const lower = normalized.toLowerCase();
  if (isArray(rules.denyList)) {
    for (const bit of rules.denyList) {
      if (isString(bit) && bit.length >= 3 && lower.includes(bit.toLowerCase())) {
        violations.push('in-deny-list');
        break;
      }
    }
  }
  if (isArray(rules.userInfo)) {
    for (const bit of rules.userInfo) {
      if (isString(bit) && bit.length >= 3 && lower.includes(bit.toLowerCase())) {
        violations.push('contains-user-info');
        break;
      }
    }
  }
  let strengthResult;
  if (isNumber(rules.requireMinScore)) {
    strengthResult = strength(normalized, { userInfo: rules.userInfo });
    if (strengthResult.score < rules.requireMinScore) {
      violations.push('below-min-strength');
    }
  }

  const out = { valid: violations.length === 0, violations };
  if (strengthResult) {
    out.strength = strengthResult;
  }
  return out;
}

/**
 * Throw-if-invalid variant. Convenient when you'd otherwise write
 * `if (!result.valid) throw new PasswordError(...)`.
 *
 * @param {unknown} password
 * @param {PolicyRules} [rules]
 * @throws {PasswordError} With `code: POLICY_VIOLATION` and
 *                         `details.violations` listing the failures.
 */
export function assertPolicy(password, rules = {}) {
  const result = policy(password, rules);
  if (!result.valid) {
    throw new PasswordError(ErrorCode.POLICY_VIOLATION, `password policy violated: ${result.violations.join(', ')}`, {
      details: { violations: result.violations, strength: result.strength },
    });
  }
}
