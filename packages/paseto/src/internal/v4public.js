/**
 * v4.public — Ed25519 signatures (PASETO §5.2).
 *
 *   sign:   m2 = PAE([h, m, f, i]); sig = Ed25519(sk, m2)
 *           token = h ‖ b64(m ‖ sig) [ ‖ "." ‖ b64(f) ]
 *   verify: split m ‖ sig, recompute m2, Ed25519 verify.
 *
 * `h` is the literal header `"v4.public."`. Raw-bytes level; JSON and
 * claim handling live one layer up.
 */

import { sign as edSign, verify as edVerify } from 'node:crypto';

import { pae } from './pae.js';
import * as b64 from './base64url.js';
import { ed25519PrivateKey, ed25519PublicKey } from './keys.js';
import { PasetoError, ErrorCode } from './errors.js';

export const HEADER = 'v4.public.';

const SIG_LEN = 64;

/**
 * @param {object} params
 * @param {Buffer} params.message
 * @param {import('node:crypto').KeyObject | Uint8Array} params.secretKey
 * @param {Buffer} [params.footer]
 * @param {Buffer} [params.implicit]
 * @returns {string}
 */
export function signRaw({ message, secretKey, footer = Buffer.alloc(0), implicit = Buffer.alloc(0) }) {
  const sk = ed25519PrivateKey(secretKey);
  const m2 = pae([Buffer.from(HEADER), message, footer, implicit]);
  const sig = edSign(null, m2, sk);

  const body = b64.encode(Buffer.concat([message, sig]));
  return footer.length > 0 ? `${HEADER}${body}.${b64.encode(footer)}` : `${HEADER}${body}`;
}

/**
 * @param {object} params
 * @param {string} params.token
 * @param {import('node:crypto').KeyObject | Uint8Array} params.publicKey
 * @param {Buffer} [params.implicit]
 * @returns {{ message: Buffer, footer: Buffer }}
 */
export function verifyRaw({ token, publicKey, implicit = Buffer.alloc(0) }) {
  const pk = ed25519PublicKey(publicKey);

  // A compact PASETO token is exactly `version.purpose.payload[.footer]`;
  // base64url never contains '.', so anything outside 3–4 segments is
  // malformed.
  const parts = token.split('.');
  if (parts.length < 3 || parts.length > 4 || `${parts[0]}.${parts[1]}.` !== HEADER) {
    throw new PasetoError(ErrorCode.INVALID_TOKEN, 'not a v4.public token');
  }
  const footer = parts.length >= 4 && parts[3] ? b64.decode(parts[3]) : Buffer.alloc(0);

  const raw = b64.decode(parts[2]);
  if (raw.length < SIG_LEN) {
    throw new PasetoError(ErrorCode.INVALID_TOKEN, 'v4.public body is too short');
  }
  const message = raw.subarray(0, raw.length - SIG_LEN);
  const sig = raw.subarray(raw.length - SIG_LEN);

  const m2 = pae([Buffer.from(HEADER), message, footer, implicit]);
  if (!edVerify(null, m2, pk, sig)) {
    throw new PasetoError(ErrorCode.SIGNATURE_INVALID, 'v4.public signature verification failed');
  }
  return { message, footer };
}
