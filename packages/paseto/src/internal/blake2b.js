/**
 * BLAKE2b (RFC 7693) — pure JS, because `node:crypto`'s `blake2b512` is
 * **unkeyed** and locked to a 64-byte digest. PASETO v4.local needs
 * *keyed* BLAKE2b with custom output lengths: 56 bytes for the KDF
 * (`Ek ‖ n2`), 32 bytes for the message-authentication tag. Neither is
 * reachable through `createHash`, so we implement the compression
 * function here.
 *
 * 64-bit lanes are carried as `BigInt`. Inputs are token-sized (a few KB
 * at most), so clarity beats the two-word-per-lane micro-optimisation.
 * Validated against the RFC 7693 Appendix A vector and the official
 * PASETO v4 test vectors.
 */

const MASK64 = (1n << 64n) - 1n;

// SHA-512 IV — also BLAKE2b's initialisation vector.
const IV = [
  0x6a09e667f3bcc908n,
  0xbb67ae8584caa73bn,
  0x3c6ef372fe94f82bn,
  0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n,
  0x9b05688c2b3e6c1fn,
  0x1f83d9abfb41bd6bn,
  0x5be0cd19137e2179n,
];

// Message-word permutation schedule (rounds cycle through the first 10 rows).
const SIGMA = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

const rotr64 = (x, n) => ((x >> n) | (x << (64n - n))) & MASK64;

/**
 * The compression function F. Mixes a 128-byte block (16 little-endian
 * 64-bit words) into the 8-word state `h`.
 *
 * @param {BigInt[]} h        8-word chaining state, mutated in place
 * @param {BigInt[]} m        16 message words (little-endian)
 * @param {BigInt}   counter  total bytes hashed so far (incl. this block)
 * @param {boolean}  last     true for the final block
 */
function compress(h, m, counter, last) {
  const v = [...h, ...IV];
  v[12] ^= counter & MASK64;
  v[13] ^= (counter >> 64n) & MASK64;
  if (last) {
    v[14] ^= MASK64;
  }

  const mix = (a, b, c, d, x, y) => {
    v[a] = (v[a] + v[b] + x) & MASK64;
    v[d] = rotr64(v[d] ^ v[a], 32n);
    v[c] = (v[c] + v[d]) & MASK64;
    v[b] = rotr64(v[b] ^ v[c], 24n);
    v[a] = (v[a] + v[b] + y) & MASK64;
    v[d] = rotr64(v[d] ^ v[a], 16n);
    v[c] = (v[c] + v[d]) & MASK64;
    v[b] = rotr64(v[b] ^ v[c], 63n);
  };

  for (let r = 0; r < 12; r++) {
    const s = SIGMA[r];
    mix(0, 4, 8, 12, m[s[0]], m[s[1]]);
    mix(1, 5, 9, 13, m[s[2]], m[s[3]]);
    mix(2, 6, 10, 14, m[s[4]], m[s[5]]);
    mix(3, 7, 11, 15, m[s[6]], m[s[7]]);
    mix(0, 5, 10, 15, m[s[8]], m[s[9]]);
    mix(1, 6, 11, 12, m[s[10]], m[s[11]]);
    mix(2, 7, 8, 13, m[s[12]], m[s[13]]);
    mix(3, 4, 9, 14, m[s[14]], m[s[15]]);
  }

  for (let i = 0; i < 8; i++) {
    h[i] ^= v[i] ^ v[i + 8];
  }
}

/** Read the 128-byte block starting at `off` as 16 little-endian words. */
function blockWords(bytes, off) {
  const view = new DataView(bytes.buffer, bytes.byteOffset + off, 128);
  const m = new Array(16);
  for (let i = 0; i < 16; i++) {
    m[i] = view.getBigUint64(i * 8, true);
  }
  return m;
}

/**
 * Keyed BLAKE2b with an arbitrary digest length.
 *
 * @param {Uint8Array} input          message bytes
 * @param {object} [opts]
 * @param {Uint8Array} [opts.key]     0–64 byte MAC/KDF key ('' → unkeyed)
 * @param {number} [opts.dkLen=64]    output length, 1–64 bytes
 * @returns {Uint8Array}
 */
export function blake2b(input, { key = new Uint8Array(0), dkLen = 64 } = {}) {
  if (dkLen < 1 || dkLen > 64) {
    throw new RangeError('blake2b: dkLen must be 1..64');
  }
  if (key.length > 64) {
    throw new RangeError('blake2b: key must be ≤ 64 bytes');
  }

  const h = IV.slice();
  // Parameter block: digest length, key length, fanout=1, depth=1.
  h[0] ^= 0x01010000n ^ (BigInt(key.length) << 8n) ^ BigInt(dkLen);

  // A key, if present, forms a full 128-byte first block.
  let msg = input;
  if (key.length > 0) {
    const keyed = new Uint8Array(128 + input.length);
    keyed.set(key, 0);
    keyed.set(input, 128);
    msg = keyed;
  }

  let counter = 0n;
  let off = 0;
  // Process every block except the last (BLAKE2b defers the final block
  // so it can flag it, even when the message is empty).
  while (msg.length - off > 128) {
    counter += 128n;
    compress(h, blockWords(msg, off), counter, false);
    off += 128;
  }

  // Final block, zero-padded to 128 bytes.
  const remaining = msg.length - off;
  const finalBlock = new Uint8Array(128);
  finalBlock.set(msg.subarray(off, off + remaining));
  counter += BigInt(remaining);
  compress(h, blockWords(finalBlock, 0), counter, true);

  const out = new Uint8Array(dkLen);
  const view = new DataView(out.buffer);
  for (let i = 0; i < dkLen; i += 8) {
    // Last chunk may be < 8 bytes: write to a scratch lane then copy.
    if (i + 8 <= dkLen) {
      view.setBigUint64(i, h[i / 8], true);
    } else {
      const lane = new Uint8Array(8);
      new DataView(lane.buffer).setBigUint64(0, h[i / 8], true);
      out.set(lane.subarray(0, dkLen - i), i);
    }
  }
  return out;
}
