/**
 * Concat KDF — the single-step KDF from NIST SP 800-56A §5.8.1, as
 * profiled for JWE ECDH-ES key agreement in RFC 7518 §4.6.2. The digest
 * is always SHA-256 regardless of curve (RFC 7518 §4.6.2).
 *
 *   OtherInfo = AlgorithmID ‖ PartyUInfo ‖ PartyVInfo ‖ SuppPubInfo
 *   where each of AlgorithmID / PartyUInfo / PartyVInfo is a 32-bit
 *   big-endian length prefix followed by the data, SuppPubInfo is the
 *   desired key length in bits as a 32-bit big-endian integer, and
 *   SuppPrivInfo is empty.
 *
 *   DerivedKey = leftmost `keyBitLength` bits of
 *     Hash(counter=1 ‖ Z ‖ OtherInfo) ‖ Hash(counter=2 ‖ …) ‖ …
 */

import { createHash } from 'node:crypto';

const HASH_BYTES = 32; // SHA-256 output

/**
 * Prefix `data` with its byte length as a 32-bit big-endian integer.
 *
 * @param {Buffer} data
 * @returns {Buffer}
 */
function lengthPrefixed(data) {
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32BE(data.length, 0);
  return Buffer.concat([prefix, data]);
}

/**
 * @param {number} value
 * @returns {Buffer} 32-bit big-endian encoding of `value`.
 */
function uint32(value) {
  const buf = Buffer.alloc(4);
  buf.writeUInt32BE(value, 0);
  return buf;
}

/**
 * Derive a key from an ECDH shared secret.
 *
 * @param {Buffer} z  The raw ECDH shared secret.
 * @param {number} keyBitLength  Desired output length in bits (e.g. 128, 256, 512).
 * @param {string} algorithmId  The `enc` value for ECDH-ES direct, or the
 *   `alg` value for ECDH-ES+A*KW (RFC 7518 §4.6.2).
 * @param {Buffer} [apu]  Agreement PartyUInfo (decoded `apu`), default empty.
 * @param {Buffer} [apv]  Agreement PartyVInfo (decoded `apv`), default empty.
 * @returns {Buffer} The derived key, `keyBitLength / 8` bytes.
 */
export function concatKdf(z, keyBitLength, algorithmId, apu = Buffer.alloc(0), apv = Buffer.alloc(0)) {
  const keyBytes = keyBitLength / 8;
  const otherInfo = Buffer.concat([
    lengthPrefixed(Buffer.from(algorithmId, 'ascii')),
    lengthPrefixed(apu),
    lengthPrefixed(apv),
    uint32(keyBitLength),
  ]);

  const reps = Math.ceil(keyBytes / HASH_BYTES);
  const blocks = [];
  for (let counter = 1; counter <= reps; counter++) {
    const hash = createHash('sha256');
    hash.update(uint32(counter));
    hash.update(z);
    hash.update(otherInfo);
    blocks.push(hash.digest());
  }
  return Buffer.concat(blocks).subarray(0, keyBytes);
}
