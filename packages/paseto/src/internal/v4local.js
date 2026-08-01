/**
 * v4.local — authenticated encryption (PASETO §5.1). Encrypt-then-MAC:
 *
 *   1. tmp = BLAKE2b(msg = "paseto-encryption-key" ‖ n, key, 56)
 *          → Ek = tmp[0..32], n2 = tmp[32..56]
 *      Ak  = BLAKE2b(msg = "paseto-auth-key-for-aead" ‖ n, key, 32)
 *   2. c  = XChaCha20(Ek, n2, message)
 *   3. t  = BLAKE2b(msg = PAE([h, n, c, f, i]), key = Ak, 32)
 *   4. token = h ‖ b64(n ‖ c ‖ t) [ ‖ "." ‖ b64(f) ]
 *
 * `h` is the literal header `"v4.local."`. Everything here operates on
 * raw bytes; JSON payloads and claim handling live one layer up.
 */

import { randomBytes, timingSafeEqual } from 'node:crypto';

import { blake2b } from './blake2b.js';
import { xchacha20 } from './xchacha20.js';
import { pae } from './pae.js';
import * as b64 from './base64url.js';
import { symmetricKey } from './keys.js';
import { PasetoError, ErrorCode } from './errors.js';

export const HEADER = 'v4.local.';

const ENCRYPTION_KEY_DOMAIN = Buffer.from('paseto-encryption-key');
const AUTH_KEY_DOMAIN = Buffer.from('paseto-auth-key-for-aead');

/** Derive `{ Ek, n2, Ak }` from the 32-byte key and 32-byte nonce. */
function deriveKeys(key, nonce) {
  const tmp = blake2b(Buffer.concat([ENCRYPTION_KEY_DOMAIN, nonce]), { key, dkLen: 56 });
  const Ek = tmp.subarray(0, 32);
  const n2 = tmp.subarray(32, 56);
  const Ak = blake2b(Buffer.concat([AUTH_KEY_DOMAIN, nonce]), { key, dkLen: 32 });
  return { Ek, n2, Ak };
}

/**
 * Encrypt raw bytes into a `v4.local` token. `nonce` is injectable only
 * so the official test vectors can be reproduced; the public API always
 * passes a fresh CSPRNG nonce.
 *
 * @param {object} params
 * @param {Buffer} params.message
 * @param {Uint8Array} params.key
 * @param {Buffer} [params.footer]
 * @param {Buffer} [params.implicit]
 * @param {Buffer} [params.nonce]     32 bytes — TEST ONLY
 * @returns {string}
 */
export function encryptRaw({ message, key, footer = Buffer.alloc(0), implicit = Buffer.alloc(0), nonce }) {
  const k = symmetricKey(key);
  const n = nonce ?? randomBytes(32);

  const { Ek, n2, Ak } = deriveKeys(k, n);
  const c = xchacha20(Ek, n2, message);
  const preAuth = pae([Buffer.from(HEADER), n, c, footer, implicit]);
  const t = blake2b(preAuth, { key: Ak, dkLen: 32 });

  const body = b64.encode(Buffer.concat([n, c, t]));
  return footer.length > 0 ? `${HEADER}${body}.${b64.encode(footer)}` : `${HEADER}${body}`;
}

/**
 * Decrypt a `v4.local` token, verifying the MAC in constant time.
 *
 * The footer is parsed from the token itself (segment 4) and returned;
 * it is authenticated via the MAC, so tampering fails closed.
 *
 * @param {object} params
 * @param {string} params.token
 * @param {Uint8Array} params.key
 * @param {Buffer} [params.implicit]
 * @returns {{ message: Buffer, footer: Buffer }}
 */
export function decryptRaw({ token, key, implicit = Buffer.alloc(0) }) {
  const k = symmetricKey(key);

  // A compact PASETO token is exactly `version.purpose.payload[.footer]`;
  // base64url never contains '.', so anything outside 3–4 segments is
  // malformed.
  const parts = token.split('.');
  if (parts.length < 3 || parts.length > 4 || `${parts[0]}.${parts[1]}.` !== HEADER) {
    throw new PasetoError(ErrorCode.INVALID_TOKEN, 'not a v4.local token');
  }
  const footer = parts.length >= 4 && parts[3] ? b64.decode(parts[3]) : Buffer.alloc(0);

  const raw = b64.decode(parts[2]);
  if (raw.length < 32 + 32) {
    throw new PasetoError(ErrorCode.INVALID_TOKEN, 'v4.local body is too short');
  }
  const n = raw.subarray(0, 32);
  const c = raw.subarray(32, raw.length - 32);
  const t = raw.subarray(raw.length - 32);

  const { Ek, n2, Ak } = deriveKeys(k, n);
  const preAuth = pae([Buffer.from(HEADER), n, c, footer, implicit]);
  const t2 = blake2b(preAuth, { key: Ak, dkLen: 32 });

  if (t.length !== t2.length || !timingSafeEqual(t, t2)) {
    throw new PasetoError(ErrorCode.DECRYPTION_FAILED, 'v4.local authentication tag mismatch');
  }

  const message = xchacha20(Ek, n2, c);
  return { message, footer };
}
