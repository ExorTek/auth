import { assertObject, assertPositiveInt, assertString } from '../internal/validate.js';
import { biasFreeSample } from '../internal/sample.js';
import { UPPER_ALPHANUM } from '../internal/alphabets.js';

// Uppercase alphanumeric — human-readable, common invoice/tracking convention.

/**
 * @typedef {object} SerialOptions
 * @property {string}  [prefix]              Literal string prepended before any random blocks (e.g. `'INV'`, `'ORD'`).
 * @property {boolean} [year=false]          Insert the current 4-digit calendar year after the prefix.
 * @property {number}  [blocks=2]            Number of random blocks. Positive integer.
 * @property {number}  [blockLen=4]          Characters per random block. Positive integer.
 * @property {string}  [separator='-']       String placed between prefix / year / blocks.
 */

/**
 * Human-readable structured business identifier.
 *
 * Composes `<prefix?><year?><block><separator><block>…` with uppercase
 * alphanumeric random blocks. Ideal for invoice numbers, order references,
 * tracking IDs, license keys and other user-visible business identifiers.
 *
 * All random blocks share a single 36-character uppercase alphanumeric
 * alphabet (`A-Z`, `0-9`), sampled bias-free.
 *
 * @param {SerialOptions} [options]
 * @returns {string}                  Composed serial identifier.
 * @throws {CryptoError}              With code `INVALID_ARGUMENT` on invalid options.
 *
 * @example
 * serial({ prefix: 'INV', blocks: 2, blockLen: 4 })
 * // → 'INV-A3F9-B2C1'
 *
 * @example
 * serial({ prefix: 'INV', year: true })
 * // → 'INV-2026-A3F9-B2C1'
 *
 * @example
 * serial({ prefix: 'ORDER', blocks: 3, blockLen: 4, separator: '.' })
 * // → 'ORDER.A3F9.B2C1.D8E5'
 *
 * @example
 * serial()  // → 'A3F9-B2C1'  (no prefix, no year, default 2 blocks × 4 chars)
 */
export function serial(options) {
  if (options !== undefined) {
    assertObject(options, 'options');
  }
  const { prefix, year = false, blocks = 2, blockLen = 4, separator = '-' } = options ?? {};

  if (prefix !== undefined) {
    assertString(prefix, 'options.prefix');
  }
  assertPositiveInt(blocks, 'options.blocks');
  assertPositiveInt(blockLen, 'options.blockLen');
  assertString(separator, 'options.separator');

  const parts = [];
  if (prefix) {
    parts.push(prefix);
  }
  if (year) {
    parts.push(String(new Date().getFullYear()));
  }
  for (let i = 0; i < blocks; i++) {
    parts.push(biasFreeSample(UPPER_ALPHANUM, blockLen));
  }
  return parts.join(separator);
}
