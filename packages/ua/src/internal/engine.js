/**
 * Regex-based parser engine with keyword pre-filtering.
 *
 * A ruleset is an array of [regexArray, propsArray] pairs.
 * Each regex is tried in order; on first match, the props array
 * describes how to map capture groups to result properties.
 *
 * Props can be:
 *   - string           → result[prop] = match[i]
 *   - [key, value]     → result[key] = value  (static assignment)
 *   - [key, fn]        → result[key] = fn(match[i])
 *   - [key, regex, replacement]        → result[key] = match[i].replace(regex, replacement)
 *   - [key, fn, ...args]              → result[key] = fn(match[i], ...args)
 */

import { isString, isArray, isFunction } from '@exortek/shared/predicates';

const MIN_HINT_LEN = 3;

function extractHint(regex) {
  const src = regex.source;

  // Skip regexes with any alternation — branch keywords are unreliable
  if (src.includes('|')) {
    return null;
  }

  // Strip escape sequences before extracting literals
  const clean = src.replace(/\\[bBdDwWsStnrfv.]/g, '\x00');
  const literals = clean.match(/[a-zA-Z][a-zA-Z0-9 /-]{2,}/g);
  if (!literals) {
    return null;
  }

  let longest = literals[0];
  for (let i = 1; i < literals.length; i++) {
    if (literals[i].length > longest.length) {
      longest = literals[i];
    }
  }
  return longest.length >= MIN_HINT_LEN ? longest.toLowerCase() : null;
}

/**
 * Build a hint index for a ruleset. Each rule pair gets the best
 * keyword hint from its regexes. Rules with no extractable hint
 * are marked null (always run).
 *
 * @param {Array} ruleset
 * @returns {Array<string|null>}
 */
export function buildHintIndex(ruleset) {
  const hints = [];
  for (let i = 0; i < ruleset.length; i += 2) {
    const regexes = ruleset[i];
    const ruleHints = [];
    let allHaveHints = true;
    for (const regex of regexes) {
      if (!regex) {
        break;
      }
      const h = extractHint(regex);
      if (h) {
        ruleHints.push(h);
      } else {
        allHaveHints = false;
      }
    }
    // Only skip a rule if every regex has a hint and none match
    hints.push(allHaveHints && ruleHints.length > 0 ? ruleHints : null);
  }
  return hints;
}

/**
 * Like applyRules but skips rule pairs whose hint keyword
 * is not found in the (lowercased) UA string.
 *
 * @param {string} ua
 * @param {string} uaLower - pre-lowercased UA
 * @param {Array} ruleset
 * @param {Array<string|null>} hints
 * @returns {Record<string, string|undefined>}
 */
export function applyRulesFiltered(ua, uaLower, ruleset, hints) {
  if (!ua || !ruleset) {
    return {};
  }

  const result = {};

  for (let i = 0, h = 0; i < ruleset.length; i += 2, h++) {
    const hint = hints[h];
    if (hint) {
      let found = false;
      for (let k = 0; k < hint.length; k++) {
        if (uaLower.indexOf(hint[k]) !== -1) {
          found = true;
          break;
        }
      }
      if (!found) {
        continue;
      }
    }

    const regexes = ruleset[i];
    const props = ruleset[i + 1];
    let matched = false;

    for (const regex of regexes) {
      if (!regex) {
        break;
      }
      const m = regex.exec(ua);
      if (!m) {
        continue;
      }

      matched = true;
      let groupIdx = 0;

      for (const prop of props) {
        const capture = m[++groupIdx];

        if (isString(prop)) {
          result[prop] = capture || undefined;
        } else if (isArray(prop)) {
          const key = prop[0];

          if (prop.length === 2) {
            if (isFunction(prop[1])) {
              result[key] = capture ? prop[1](capture) : undefined;
            } else {
              result[key] = prop[1];
            }
          } else if (prop.length === 3) {
            if (isFunction(prop[1])) {
              result[key] = capture ? prop[1](capture, prop[2]) : undefined;
            } else if (prop[1] instanceof RegExp) {
              result[key] = capture ? capture.replace(prop[1], prop[2]) : undefined;
            }
          } else if (prop.length >= 4) {
            if (prop[1] instanceof RegExp && isFunction(prop[3])) {
              result[key] = capture ? prop[3](capture.replace(prop[1], prop[2])) : undefined;
            }
          }
        }
      }
      break;
    }

    if (matched) {
      return result;
    }
  }

  return result;
}
