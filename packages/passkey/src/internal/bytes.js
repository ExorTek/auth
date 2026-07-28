/**
 * Byte-array helpers shared across attestation formats.
 *
 * `bytesEqual` is constant-time in the sense that it doesn't
 * short-circuit past the length check — every equal-length input
 * runs through the full XOR loop. WebAuthn attestations are not
 * timing-sensitive (they compare public material), but keeping the
 * comparator branchless avoids the whole class of "was this constant-
 * time?" review questions.
 *
 * `concat` is the trivial many-input Uint8Array joiner that every
 * attestation verifier hand-rolled.
 */

/**
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @returns {boolean}
 */
export function bytesEqual(a, b) {
  if (a.byteLength !== b.byteLength) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.byteLength; i += 1) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/**
 * @param {...Uint8Array} chunks
 * @returns {Uint8Array}
 */
export function concat(...chunks) {
  let total = 0;
  for (const c of chunks) {
    total += c.byteLength;
  }
  const out = new Uint8Array(total);
  let pos = 0;
  for (const c of chunks) {
    out.set(c, pos);
    pos += c.byteLength;
  }
  return out;
}
