/**
 * XChaCha20 — the 24-byte-nonce ChaCha20 variant PASETO v4.local
 * encrypts with. `node:crypto` ships `chacha20` (RFC 8439, 12-byte
 * nonce) but not XChaCha20, so we derive the subkey with HChaCha20 here
 * and delegate the actual keystream to the native cipher:
 *
 *   subkey       = HChaCha20(key, nonce[0..16])
 *   chachaNonce  = 0x00000000 ‖ nonce[16..24]        (12 bytes)
 *   keystream    = ChaCha20(subkey, chachaNonce, counter = 0)
 *
 * Only HChaCha20 (16 quarter-round rounds, no feed-forward add) runs in
 * JS; the bulk stream stays in OpenSSL. Validated against the HChaCha20
 * vector in draft-irtf-cfrg-xchacha and the PASETO v4 test vectors.
 */

import { createCipheriv } from 'node:crypto';

// "expand 32-byte k"
const C0 = 0x61707865;
const C1 = 0x3320646e;
const C2 = 0x79622d32;
const C3 = 0x6b206574;

const rotl = (x, n) => (x << n) | (x >>> (32 - n));

/**
 * HChaCha20 subkey derivation. Runs the ChaCha20 permutation over the
 * key + first 16 nonce bytes and returns words 0–3 and 12–15 — the
 * feed-forward addition of the plain ChaCha20 block is deliberately
 * omitted.
 *
 * @param {Uint8Array} key    32 bytes
 * @param {Uint8Array} nonce  16 bytes
 * @returns {Buffer} 32-byte subkey
 */
export function hchacha20(key, nonce) {
  const k = new DataView(key.buffer, key.byteOffset, 32);
  const n = new DataView(nonce.buffer, nonce.byteOffset, 16);

  const s = new Int32Array(16);
  s[0] = C0;
  s[1] = C1;
  s[2] = C2;
  s[3] = C3;
  for (let i = 0; i < 8; i++) {
    s[4 + i] = k.getUint32(i * 4, true) | 0;
  }
  for (let i = 0; i < 4; i++) {
    s[12 + i] = n.getUint32(i * 4, true) | 0;
  }

  const qr = (a, b, c, d) => {
    s[a] += s[b];
    s[d] = rotl(s[d] ^ s[a], 16);
    s[c] += s[d];
    s[b] = rotl(s[b] ^ s[c], 12);
    s[a] += s[b];
    s[d] = rotl(s[d] ^ s[a], 8);
    s[c] += s[d];
    s[b] = rotl(s[b] ^ s[c], 7);
  };

  for (let r = 0; r < 10; r++) {
    qr(0, 4, 8, 12);
    qr(1, 5, 9, 13);
    qr(2, 6, 10, 14);
    qr(3, 7, 11, 15);
    qr(0, 5, 10, 15);
    qr(1, 6, 11, 12);
    qr(2, 7, 8, 13);
    qr(3, 4, 9, 14);
  }

  const out = Buffer.allocUnsafe(32);
  const words = [0, 1, 2, 3, 12, 13, 14, 15];
  for (let i = 0; i < 8; i++) {
    out.writeUInt32LE(s[words[i]] >>> 0, i * 4);
  }
  return out;
}

/**
 * XChaCha20 keystream cipher (counter starts at 0). Symmetric — the
 * same call encrypts and decrypts.
 *
 * @param {Uint8Array} key     32 bytes
 * @param {Uint8Array} nonce   24 bytes
 * @param {Uint8Array} input   plaintext or ciphertext
 * @returns {Buffer}
 */
export function xchacha20(key, nonce, input) {
  const subkey = hchacha20(key, nonce.subarray(0, 16));

  // OpenSSL's `chacha20` IV is 16 bytes: 32-bit LE counter ‖ 96-bit
  // nonce. Counter = 0, nonce = 0x00000000 ‖ last 8 nonce bytes.
  const iv = Buffer.alloc(16);
  Buffer.from(nonce.subarray(16, 24)).copy(iv, 8);

  const cipher = createCipheriv('chacha20', subkey, iv);
  return Buffer.concat([cipher.update(input), cipher.final()]);
}
