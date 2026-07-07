import { assertString } from '../internal/validate.js';
import { CryptoError, ErrorCode } from '../errors.js';
import { biasFreeSample } from '../internal/sample.js';
import { ALPHANUM, DIGITS, LOWER, UPPER } from '../internal/alphabets.js';

// Cache alphabet per placeholder to avoid the switch on every character.
const PLACEHOLDERS = {
  X: ALPHANUM,
  A: UPPER,
  a: LOWER,
  '#': DIGITS,
};

/**
 * Pattern-based random code generator.
 *
 * Each placeholder in `pattern` is replaced by a bias-free random character
 * from a fixed alphabet; every other character is emitted verbatim as a
 * literal (separator, prefix, group boundary…).
 *
 * Placeholder DSL:
 * | Char | Alphabet                         | Example |
 * |------|----------------------------------|---------|
 * | `X`  | `[A-Za-z0-9]` (62 chars)         | `V1r`   |
 * | `A`  | `[A-Z]` (26 chars, uppercase)    | `KMP`   |
 * | `a`  | `[a-z]` (26 chars, lowercase)    | `kmp`   |
 * | `#`  | `[0-9]` (10 digits)              | `847`   |
 *
 * Any other character in the pattern is copied literally to the output —
 * useful for dashes, spaces, brand prefixes, etc.
 *
 * @param {string} pattern  Non-empty pattern string.
 * @returns {string}        Generated code, length equal to `pattern.length`.
 * @throws {CryptoError}    With code `INVALID_ARGUMENT` if `pattern` is not a non-empty string.
 *
 * @example
 * code('XXX-XXX')     // 'A3F-9K2'    — mixed-case alphanumeric groups
 * code('####-####')   // '2941-8362'  — digit-only card style
 * code('XX##XX##')    // 'A3B2C4D9'   — inline mix
 * code('AAAA')        // 'ZKMP'       — uppercase 4-char shortcode
 * code('SK_XXXX')     // 'SK_H29B'    — literal prefix + random suffix
 */
export function code(pattern) {
  assertString(pattern, 'pattern');
  if (pattern.length === 0) {
    throw new CryptoError(
      ErrorCode.INVALID_ARGUMENT,
      "pattern must be a non-empty string. Use placeholders X (alphanumeric), A (uppercase letter), a (lowercase letter), # (digit); anything else stays literal. Example: 'XXXX-####' → 'AB3F-8127'.",
    );
  }

  let out = '';
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i];
    const alphabet = PLACEHOLDERS[ch];
    if (alphabet !== undefined) {
      out += biasFreeSample(alphabet, 1);
    } else {
      out += ch;
    }
  }
  return out;
}
