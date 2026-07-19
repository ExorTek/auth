import { verify as umbrellaVerify } from './verify.js';
import { assertNonEmptyString, invalidArgument } from './internal/guards.js';

/**
 * @typedef {object} HistoryConfig
 * @property {number} [keepLast=5]
 *   Number of previous hashes to compare against. Some regulations
 *   (e.g. PCI-DSS 8.3.7) require ≥ 4; NIST-2020 §5.1.1.2 discourages
 *   password rotation entirely, so leaving this at a modest value is
 *   fine.
 */

/**
 * Password history helper — enforces "don't reuse the last N passwords".
 * The library stays stateless: you feed it a list of previously stored
 * hashes and it walks them for you. All comparisons use the umbrella
 * `verify` router, so the history list can be mixed-algorithm during
 * migration.
 *
 * @example
 * const history = createHistory({ keepLast: 5 })
 * if (await history.isReused(newPw, user.previousHashes)) {
 *   throw new PasswordError(ErrorCode.REUSED_PASSWORD, 'cannot reuse a recent password')
 * }
 * const newHash = await password.scrypt.hash(newPw)
 * await db.users.update(user.id, {
 *   pw_hash: newHash,
 *   previous_hashes: history.append(newHash, user.previousHashes),
 * })
 *
 * @param {HistoryConfig} [config]
 */
export function createHistory(config = {}) {
  const keepLast = config.keepLast ?? 5;
  if (!Number.isInteger(keepLast) || keepLast < 1 || keepLast > 64) {
    throw invalidArgument(`createHistory.config.keepLast must be an integer in [1, 64]; got ${keepLast}`);
  }
  return {
    /**
     * Check whether a candidate password matches any of the given
     * previous hashes. Returns `true` on first match; walks the list
     * left-to-right (newest-first is the natural storage order).
     *
     * @param {string | Buffer | Uint8Array} candidate
     * @param {readonly string[]} previousHashes
     * @returns {Promise<boolean>}
     */
    async isReused(candidate, previousHashes) {
      if (!Array.isArray(previousHashes) || previousHashes.length === 0) {
        return false;
      }
      const slice = previousHashes.slice(0, keepLast);
      for (const stored of slice) {
        if (typeof stored !== 'string' || stored.length === 0) {
          continue;
        }
        const match = await umbrellaVerify(candidate, stored);
        if (match) {
          return true;
        }
      }
      return false;
    },

    /**
     * Prepend a fresh hash onto the previous-hashes list and trim to
     * `keepLast`. Returns a new array — the input is not mutated.
     *
     * @param {string} freshHash          The hash of the newly-chosen password.
     * @param {readonly string[]} previousHashes
     * @returns {string[]}
     */
    append(freshHash, previousHashes) {
      assertNonEmptyString(freshHash, 'history.append.freshHash');
      const prev = Array.isArray(previousHashes) ? previousHashes : [];
      const merged = [freshHash, ...prev.filter(h => h !== freshHash)];
      return merged.slice(0, keepLast);
    },
  };
}
