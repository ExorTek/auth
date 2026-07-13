// PHC strings use unpadded base64 (RFC 7468 §4 without the '=' terminators).
// Node's Buffer 'base64' encoding always pads on emit — strip it. Decode
// tolerates padding, so we just accept whatever the input has.

/** @param {Buffer | Uint8Array} bytes */
export function b64Encode(bytes) {
  return Buffer.from(bytes).toString('base64').replace(/=+$/, '');
}

/** @param {string} s */
export function b64Decode(s) {
  return Buffer.from(s, 'base64');
}
