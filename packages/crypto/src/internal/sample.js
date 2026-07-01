import crypto from 'node:crypto';

/**
 * Bias-free rejection sampling from an arbitrary alphabet.
 *
 * Draws random bytes and, for each byte < the largest multiple of the
 * alphabet length that fits in `[0, 256)`, maps it to a character. Bytes at
 * or above the threshold are rejected to avoid modulo bias — the resulting
 * character distribution is exactly uniform.
 *
 * Over-provisions the byte batch by 60% to keep `crypto.randomBytes` syscall
 * count low even when some bytes are rejected.
 *
 * @private
 * @param {string} alphabet  Non-empty character set to sample from. Length must be > 0.
 * @param {number} length    Number of characters to emit. Positive integer expected.
 * @returns {string}
 */
export function biasFreeSample(alphabet, length) {
  const alphabetLen = alphabet.length;
  const threshold = 256 - (256 % alphabetLen);

  let out = '';
  while (out.length < length) {
    const remaining = length - out.length;
    const batch = crypto.randomBytes(Math.ceil(remaining * 1.6));
    for (let i = 0; i < batch.length && out.length < length; i++) {
      if (batch[i] < threshold) {
        out += alphabet[batch[i] % alphabetLen];
      }
    }
  }
  return out;
}
