/**
 * RFC 4226 §5.3 — dynamic truncation.
 *
 * Given an HMAC output (H) and a target digit width (N), produce the N-
 * digit OTP:
 *
 *   1. offset = H[19] & 0x0f              (the low 4 bits of the last byte)
 *   2. bin    = H[offset .. offset+3]     (4 bytes big-endian) & 0x7fffffff
 *   3. code   = bin % 10^N                (numeric N-digit string, left-padded)
 *
 * The mask on the top byte drops the sign bit so we never build a
 * negative int on platforms where 4-byte reads are signed. This is a
 * hot path — called once per verify + up to (2*window+1) attempts —
 * so we keep it allocation-free.
 *
 * @param {Buffer} hmac    Full HMAC digest (20/32/64 bytes depending on algorithm).
 * @param {number} digits  Target OTP length, 6-10.
 * @returns {string}       Zero-padded N-digit code.
 */
export function truncate(hmac, digits) {
  const offset = hmac[hmac.length - 1] & 0x0f;
  const bin =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  const code = bin % 10 ** digits;
  return String(code).padStart(digits, '0');
}
