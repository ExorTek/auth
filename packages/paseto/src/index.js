/**
 * `@exortek/paseto` — Platform-Agnostic Security Tokens for Node.js 22+.
 *
 *   - v4.local  — XChaCha20 + keyed BLAKE2b, encrypt-then-MAC (PASETO v4)
 *   - v4.public — Ed25519 signatures (PASETO v4)
 *
 * Unlike JWT, the token's `vN.purpose.` prefix binds the primitive set:
 * there is no negotiable `alg` header, so algorithm-confusion attacks are
 * structurally impossible. Server-only, zero-dependency, built on
 * `node:crypto` (with a vendored keyed-BLAKE2b + HChaCha20, which the
 * platform does not expose).
 *
 * Named exports for tree-shaking, plus a frozen `paseto` namespace that
 * mirrors the ARCHITECTURE example.
 */

import { encrypt, decrypt } from './local.js';
import { sign, verify } from './public.js';
import { decode } from './decode.js';
import { generateKey, generateKeyPair } from './keygen.js';
import { PasetoError, ErrorCode } from './internal/errors.js';
import { SUPPORTED } from './internal/versions.js';

export { encrypt, decrypt, sign, verify, decode, generateKey, generateKeyPair };
export { PasetoError, ErrorCode, SUPPORTED };

/**
 * Bundled namespace matching the ARCHITECTURE example.
 */
export const paseto = Object.freeze({
  generateKey,
  generateKeyPair,
  encrypt,
  decrypt,
  sign,
  verify,
  decode,
});

/**
 * @typedef {import('./local.js').EncryptOptions} EncryptOptions
 * @typedef {import('./local.js').DecryptOptions} DecryptOptions
 */
