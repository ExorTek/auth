/**
 * @typedef {'too-short' | 'single-class' | 'repetition' | 'sequential' | 'contains-user-info'} Weakness
 */

/**
 * @typedef {object} StrengthResult
 * @property {0 | 1 | 2 | 3 | 4} score
 *   Coarse strength bucket:
 *     0 — trivially crackable (single dictionary hit, tiny alphabet).
 *     1 — cracked in seconds on a laptop.
 *     2 — cracked in hours to days on a small GPU cluster.
 *     3 — cracked in years on modest hardware.
 *     4 — infeasible on foreseeable hardware.
 *   Score is deliberately coarse — zxcvbn-style multi-class regression
 *   is out of scope for this package. If you need higher-fidelity
 *   scoring, run `zxcvbn` in your form validator and use this as a
 *   backend sanity check.
 * @property {number} entropyBits
 *   Rough Shannon entropy in bits, computed as
 *   `length × log2(effectiveAlphabet)` after collapsing repeats.
 *   Real entropy of a *human-chosen* password is much lower; treat this
 *   as an upper bound.
 * @property {Weakness[]} weaknesses
 *   Machine-readable reasons the score is what it is. Empty for score 4.
 * @property {number} lengthAfterNormalize
 *   Unicode-normalized length (NFKC). Handy for policy checks that want
 *   to enforce a display-length rather than raw byte count.
 */

import { isArray, isString } from '@exortek/shared/predicates';

/**
 * @typedef {object} StrengthOptions
 * @property {string[]} [userInfo]
 *   Substrings — usually the user's email, username, first name — that
 *   should not appear inside the password. Case-insensitive.
 */

// Character classes we score against. `symbol` covers ASCII printable
// non-alnum; extended-Unicode symbols count under `other`.
const CLASSES = /** @type {const} */ ([
  { name: 'lower', re: /[a-z]/, size: 26 },
  { name: 'upper', re: /[A-Z]/, size: 26 },
  { name: 'digit', re: /[0-9]/, size: 10 },
  { name: 'symbol', re: /[!-/:-@[-`{-~]/, size: 32 },
  { name: 'other', re: /[^\x20-\x7e]/, size: 100 },
]);

/**
 * Score how weak a candidate password is. Runs entirely offline —
 * common-password check, character-class entropy estimate, repetition
 * / sequential-run detection, and optional user-info substring match.
 *
 * @param {unknown} password
 * @param {StrengthOptions} [options]
 * @returns {StrengthResult}
 */
export function strength(password, options = {}) {
  if (!isString(password) || password.length === 0) {
    return {
      score: 0,
      entropyBits: 0,
      weaknesses: ['too-short'],
      lengthAfterNormalize: 0,
    };
  }
  const normalized = password.normalize('NFKC');
  const weaknesses = [];

  if (normalized.length < 8) {
    weaknesses.push('too-short');
  }

  let alphabet = 0;
  let classesPresent = 0;
  for (const cls of CLASSES) {
    if (cls.re.test(normalized)) {
      alphabet += cls.size;
      classesPresent++;
    }
  }
  if (classesPresent <= 1) {
    weaknesses.push('single-class');
  }

  if (hasLongRepetition(normalized)) {
    weaknesses.push('repetition');
  }
  if (hasSequentialRun(normalized)) {
    weaknesses.push('sequential');
  }

  const userInfo = isArray(options.userInfo) ? options.userInfo : [];
  const lower = normalized.toLowerCase();
  for (const bit of userInfo) {
    if (isString(bit) && bit.length >= 3 && lower.includes(bit.toLowerCase())) {
      weaknesses.push('contains-user-info');
      break;
    }
  }

  const entropyBits = alphabet > 0 ? normalized.length * Math.log2(alphabet) : 0;

  // Coarse bucketing. Anything under 6 characters collapses to 0
  // regardless of alphabet; otherwise map bits → score.
  let score;
  if (weaknesses.includes('too-short') && normalized.length < 6) {
    score = 0;
  } else if (entropyBits < 28) {
    score = 1;
  } else if (entropyBits < 60) {
    score = 2;
  } else if (entropyBits < 128) {
    score = 3;
  } else {
    score = 4;
  }
  // Downgrade if there are structural weaknesses regardless of raw bit count.
  if (score > 0 && (weaknesses.includes('sequential') || weaknesses.includes('repetition'))) {
    score = Math.max(1, score - 1);
  }
  if (score > 0 && weaknesses.includes('contains-user-info')) {
    score = Math.max(1, score - 2);
  }

  return {
    score: /** @type {0 | 1 | 2 | 3 | 4} */ (score),
    entropyBits: Math.round(entropyBits * 10) / 10,
    weaknesses,
    lengthAfterNormalize: normalized.length,
  };
}

function hasLongRepetition(s) {
  // 3+ of the same character in a row → "aaaa", "1111"
  return /(.)\1{2,}/.test(s);
}

function hasSequentialRun(s) {
  // 4+ characters in an ascending/descending run of consecutive code points —
  // catches "1234", "abcd", "wxyz", "9876".
  if (s.length < 4) {
    return false;
  }
  let up = 1;
  let down = 1;
  for (let i = 1; i < s.length; i++) {
    const diff = s.charCodeAt(i) - s.charCodeAt(i - 1);
    if (diff === 1) {
      up++;
      down = 1;
    } else if (diff === -1) {
      down++;
      up = 1;
    } else {
      up = 1;
      down = 1;
    }
    if (up >= 4 || down >= 4) {
      return true;
    }
  }
  return false;
}
