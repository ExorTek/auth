/**
 * Origin allowlist patterns. A `RegExp` with the `g` or `y` flag keeps
 * `lastIndex` between `.test()` calls, so the same origin alternately
 * matches and fails — a CORS or Origin check that flips per request. And an
 * unanchored pattern such as `/https:\/\/app\.example\.com/` also matches
 * `https://app.example.com.evil.net`.
 *
 * `statelessPattern` strips the stateful flags (memoised per pattern) and
 * warns once about a pattern with no `$` end anchor — the omission that lets
 * an attacker append their own domain. (A `^`-less suffix pattern like
 * `/\.example\.com$/` is a deliberate subdomain match and stays quiet.)
 */

/** @type {WeakMap<RegExp, RegExp>} */
const compiled = new WeakMap();

/**
 * @param {RegExp} pattern
 * @param {string} where   option name, for the warning
 * @returns {RegExp}
 */
export function statelessPattern(pattern, where) {
  let out = compiled.get(pattern);
  if (out) {
    return out;
  }
  out = /[gy]/.test(pattern.flags) ? new RegExp(pattern.source, pattern.flags.replace(/[gy]/g, '')) : pattern;
  if (!pattern.source.endsWith('$')) {
    process.emitWarning(
      `${where} pattern ${pattern} has no $ end anchor, so it also matches origins with anything appended`,
      { code: 'EXORTEK_SECURITY_UNANCHORED_ORIGIN' },
    );
  }
  compiled.set(pattern, out);
  return out;
}
