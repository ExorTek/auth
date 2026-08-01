/**
 * PAE — Pre-Authentication Encoding (PASETO §Authentication Padding).
 * Serialises the pieces that go under the MAC / signature so that no
 * choice of field contents can be re-parsed as a different field split
 * (canonical, unambiguous length-prefixing):
 *
 *   PAE(pieces) = LE64(pieces.length) ‖ ∀p: LE64(p.length) ‖ p
 *
 * `LE64` is a 64-bit little-endian length with the top bit forced to 0
 * — the spec clears it so implementations in languages without unsigned
 * 64-bit integers stay interoperable.
 */

/**
 * Encode `n` as an 8-byte little-endian length with bit 63 cleared.
 * @param {number} n
 * @returns {Buffer}
 */
function le64(n) {
  const buf = Buffer.alloc(8);
  // Safe-integer range covers any realistic token; clear the MSB per spec.
  buf.writeBigUint64LE(BigInt(n) & 0x7fffffffffffffffn, 0);
  return buf;
}

/**
 * Pre-Authentication Encoding of an ordered list of byte pieces.
 * @param {Array<Uint8Array | Buffer>} pieces
 * @returns {Buffer}
 */
export function pae(pieces) {
  const out = [le64(pieces.length)];
  for (const piece of pieces) {
    out.push(le64(piece.length), Buffer.from(piece));
  }
  return Buffer.concat(out);
}
