/**
 * Bounds shared by every verify path for values read back from a stored
 * hash string, which may have been tampered with.
 */

// Real digests are 16–64 bytes; anything else is malformed — and a huge
// length makes PBKDF2 / scrypt / Argon2 produce (and pay for) that many
// output bytes.
const MIN_HASH_BYTES = 16;
const MAX_HASH_BYTES = 64;

/**
 * @param {Uint8Array} hash
 * @returns {boolean}
 */
export function isSaneHashLength(hash) {
  return hash.length >= MIN_HASH_BYTES && hash.length <= MAX_HASH_BYTES;
}
