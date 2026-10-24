/**
 * BLAKE2b (RFC 7693) — pure JS, because `node:crypto`'s `blake2b512` is
 * **unkeyed** and locked to a 64-byte digest. PASETO v4.local needs
 * *keyed* BLAKE2b with custom output lengths: 56 bytes for the KDF
 * (`Ek ‖ n2`), 32 bytes for the message-authentication tag. Neither is
 * reachable through `createHash`, so we implement the compression
 * function here.
 *
 * Each 64-bit lane is carried as two 32-bit halves (low word first) in a
 * `Uint32Array`, so the hot loop is plain integer arithmetic with no
 * allocation — the BigInt formulation cost ~150 µs per kilobyte.
 * Validated against the RFC 7693 Appendix A vector, the official PASETO v4
 * test vectors, and node's own (unkeyed) `blake2b512`.
 */

// SHA-512 IV — also BLAKE2b's initialisation vector — as [lo, hi] halves.
const IV = new Uint32Array([
  0xf3bcc908, 0x6a09e667, 0x84caa73b, 0xbb67ae85, 0xfe94f82b, 0x3c6ef372, 0x5f1d36f1, 0xa54ff53a, 0xade682d1,
  0x510e527f, 0x2b3e6c1f, 0x9b05688c, 0xfb41bd6b, 0x1f83d9ab, 0x137e2179, 0x5be0cd19,
]);

// Message-word permutation schedule (rounds cycle through the first 10
// rows), pre-doubled to index the [lo, hi] word pairs directly.
const SIGMA = new Uint8Array(
  [
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
  ]
    .flat()
    .map(i => i * 2),
);

// Working vector and message words, reused across calls (single-threaded).
const v = new Uint32Array(32);
const m = new Uint32Array(32);

/** v[a] += v[b] (64-bit, lane indices are word offsets). */
function add64(a, b) {
  const lo = v[a] + v[b];
  v[a + 1] = v[a + 1] + v[b + 1] + (lo >= 0x100000000 ? 1 : 0);
  v[a] = lo;
}

/** v[a] += m[x] (64-bit). */
function add64m(a, x) {
  const lo = v[a] + m[x];
  v[a + 1] = v[a + 1] + m[x + 1] + (lo >= 0x100000000 ? 1 : 0);
  v[a] = lo;
}

/** The G mixing function on lanes a, b, c, d with message words x, y. */
function mix(a, b, c, d, x, y) {
  add64(a, b);
  add64m(a, x);
  // v[d] = rotr64(v[d] ^ v[a], 32)
  let lo = v[d] ^ v[a];
  let hi = v[d + 1] ^ v[a + 1];
  v[d] = hi;
  v[d + 1] = lo;
  add64(c, d);
  // v[b] = rotr64(v[b] ^ v[c], 24)
  lo = v[b] ^ v[c];
  hi = v[b + 1] ^ v[c + 1];
  v[b] = (lo >>> 24) | (hi << 8);
  v[b + 1] = (hi >>> 24) | (lo << 8);
  add64(a, b);
  add64m(a, y);
  // v[d] = rotr64(v[d] ^ v[a], 16)
  lo = v[d] ^ v[a];
  hi = v[d + 1] ^ v[a + 1];
  v[d] = (lo >>> 16) | (hi << 16);
  v[d + 1] = (hi >>> 16) | (lo << 16);
  add64(c, d);
  // v[b] = rotr64(v[b] ^ v[c], 63) — i.e. rotl 1
  lo = v[b] ^ v[c];
  hi = v[b + 1] ^ v[c + 1];
  v[b] = (hi >>> 31) | (lo << 1);
  v[b + 1] = (lo >>> 31) | (hi << 1);
}

/**
 * The compression function F over the 128-byte block at `bytes[off]`.
 *
 * @param {Uint32Array} h        16-word chaining state, mutated in place
 * @param {Uint8Array} bytes
 * @param {number} off
 * @param {number} counter       total bytes hashed so far (incl. this block); < 2^53
 * @param {boolean} last
 */
function compress(h, bytes, off, counter, last) {
  for (let i = 0; i < 16; i++) {
    v[i] = h[i];
    v[i + 16] = IV[i];
  }
  v[24] ^= counter >>> 0;
  v[25] ^= Math.floor(counter / 0x100000000);
  if (last) {
    v[28] = ~v[28];
    v[29] = ~v[29];
  }
  for (let i = 0; i < 32; i++) {
    const p = off + i * 4;
    m[i] = bytes[p] | (bytes[p + 1] << 8) | (bytes[p + 2] << 16) | (bytes[p + 3] << 24);
  }
  for (let r = 0; r < 12; r++) {
    const s = r * 16;
    mix(0, 8, 16, 24, SIGMA[s], SIGMA[s + 1]);
    mix(2, 10, 18, 26, SIGMA[s + 2], SIGMA[s + 3]);
    mix(4, 12, 20, 28, SIGMA[s + 4], SIGMA[s + 5]);
    mix(6, 14, 22, 30, SIGMA[s + 6], SIGMA[s + 7]);
    mix(0, 10, 20, 30, SIGMA[s + 8], SIGMA[s + 9]);
    mix(2, 12, 22, 24, SIGMA[s + 10], SIGMA[s + 11]);
    mix(4, 14, 16, 26, SIGMA[s + 12], SIGMA[s + 13]);
    mix(6, 8, 18, 28, SIGMA[s + 14], SIGMA[s + 15]);
  }
  for (let i = 0; i < 16; i++) {
    h[i] ^= v[i] ^ v[i + 16];
  }
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
  h[0] ^= 0x01010000 ^ (key.length << 8) ^ dkLen;

  const block = new Uint8Array(128);
  let counter = 0;

  // A key, if present, forms a full 128-byte first block — the last one
  // only when there is no message after it.
  if (key.length > 0) {
    block.set(key);
    counter = 128;
    compress(h, block, 0, counter, input.length === 0);
    if (input.length === 0) {
      return output(h, dkLen);
    }
  }

  // Every block except the last (BLAKE2b defers the final block so it can
  // flag it, even when the message is empty).
  let off = 0;
  while (input.length - off > 128) {
    counter += 128;
    compress(h, input, off, counter, false);
    off += 128;
  }

  // Final block, zero-padded to 128 bytes.
  const remaining = input.length - off;
  block.fill(0);
  block.set(input.subarray(off, off + remaining));
  counter += remaining;
  compress(h, block, 0, counter, true);
  return output(h, dkLen);
}

/**
 * @param {Uint32Array} h
 * @param {number} dkLen
 * @returns {Uint8Array}
 */
function output(h, dkLen) {
  const out = new Uint8Array(dkLen);
  for (let i = 0; i < dkLen; i++) {
    out[i] = h[i >>> 2] >>> (8 * (i & 3));
  }
  return out;
}
