/**
 * Bias-free CSPRNG rejection sampling — the single implementation
 * behind every `@exortek/*` random-alphabet primitive that used to
 * carry its own `biasFreeSample` / `draw()` / inline rejection loop.
 *
 * Two primitives cover the current callers:
 *
 * - {@link sampleAlphabet} — byte-based sampling from a string
 *   alphabet (1-256 characters). Draws random bytes and maps every
 *   byte below the largest alphabet-length multiple in `[0, 256)` to
 *   a character. Bytes at or above the threshold are rejected, so the
 *   emitted distribution is exactly uniform.
 *
 * - {@link sampleUint16Indices} — same idea but on `UInt16BE` chunks,
 *   for callers that draw from a range wider than 256 (word lists,
 *   large lookup tables). Returns an `Int32Array` of indices in
 *   `[0, maxExclusive)`; the caller maps them.
 *
 * Both over-provision the byte batch (`×2`) so the rejection loop
 * rarely forces a second `randomBytes` syscall — a single-digit
 * percentage of bytes get rejected in the worst case, so ×2 is more
 * than enough to finish a draw in one pass.
 *
 * Failures throw plain `Error`; consumers already sit behind a bound
 * guard, so no wrapping is needed here.
 */

import { randomBytes } from 'node:crypto';

/**
 * Bias-free sample of `length` characters from `alphabet`.
 *
 * @param {string} alphabet     Non-empty character set to sample from
 *                              (1-256 chars).
 * @param {number} length       Number of characters to emit
 *                              (non-negative safe integer).
 * @returns {string}
 * @throws {Error} on bad alphabet or bad length.
 */
export function sampleAlphabet(alphabet, length) {
  if (typeof alphabet !== 'string' || alphabet.length === 0 || alphabet.length > 256) {
    throw new Error(
      `sampleAlphabet: alphabet must be a string of 1-256 characters; got ${typeof alphabet === 'string' ? `length ${alphabet.length}` : typeof alphabet}`,
    );
  }
  if (!Number.isSafeInteger(length) || length < 0) {
    throw new Error(`sampleAlphabet: length must be a non-negative safe integer; got ${length}`);
  }
  if (length === 0) {
    return '';
  }

  const alphabetLen = alphabet.length;
  const threshold = 256 - (256 % alphabetLen);

  let out = '';
  while (out.length < length) {
    const remaining = length - out.length;
    const batch = randomBytes(Math.max(1, remaining * 2));
    for (let i = 0; i < batch.length && out.length < length; i++) {
      if (batch[i] < threshold) {
        out += alphabet[batch[i] % alphabetLen];
      }
    }
  }
  return out;
}

/**
 * Bias-free sample of `count` integer indices in `[0, maxExclusive)`.
 * Uses `UInt16BE` chunks so `maxExclusive` up to `2^16` is supported
 * — the intended callers are word-list draws (256 words today, larger
 * lists likely).
 *
 * @param {number} maxExclusive  Upper bound (exclusive) — integer in
 *                               `[1, 65_536]`.
 * @param {number} count         Non-negative safe integer.
 * @returns {number[]}
 * @throws {Error} on bad range or bad count.
 */
export function sampleUint16Indices(maxExclusive, count) {
  if (!Number.isSafeInteger(maxExclusive) || maxExclusive < 1 || maxExclusive > 65_536) {
    throw new Error(`sampleUint16Indices: maxExclusive must be an integer in [1, 65536]; got ${maxExclusive}`);
  }
  if (!Number.isSafeInteger(count) || count < 0) {
    throw new Error(`sampleUint16Indices: count must be a non-negative safe integer; got ${count}`);
  }
  if (count === 0) {
    return [];
  }

  const threshold = 65_536 - (65_536 % maxExclusive);
  const out = new Array(count);
  let filled = 0;
  while (filled < count) {
    // 2 bytes per index; over-provision ×2 so a single draw finishes.
    const remaining = count - filled;
    const batch = randomBytes(Math.max(2, remaining * 2 * 2));
    for (let i = 0; i + 1 < batch.length && filled < count; i += 2) {
      const v = batch.readUInt16BE(i);
      if (v < threshold) {
        out[filled++] = v % maxExclusive;
      }
    }
  }
  return out;
}
