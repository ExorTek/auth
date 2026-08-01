/**
 * Key generation for the two v4 purposes.
 *
 *   - `generateKey()`      → 32-byte symmetric key for v4.local
 *   - `generateKeyPair()`  → Ed25519 { secretKey (64B), publicKey (32B) }
 *     in PASETO's raw wire form (`secretKey = seed ‖ public`).
 */

import { randomBytes, generateKeyPairSync } from 'node:crypto';

import { rawFromKeyObject } from './internal/keys.js';
import { V4_LOCAL, V4_PUBLIC } from './internal/versions.js';
import { PasetoError, ErrorCode } from './internal/errors.js';

/**
 * Generate a symmetric key for `v4.local`.
 * @param {string} [version='v4.local']
 * @returns {Buffer} 32 random bytes
 */
export function generateKey(version = V4_LOCAL) {
  if (version !== V4_LOCAL) {
    throw new PasetoError(ErrorCode.UNSUPPORTED_VERSION, `generateKey supports '${V4_LOCAL}', got '${version}'`);
  }
  return randomBytes(32);
}

/**
 * Generate an Ed25519 key pair for `v4.public`, in raw wire form.
 * @param {string} [version='v4.public']
 * @returns {{ secretKey: Buffer, publicKey: Buffer }}
 */
export function generateKeyPair(version = V4_PUBLIC) {
  if (version !== V4_PUBLIC) {
    throw new PasetoError(ErrorCode.UNSUPPORTED_VERSION, `generateKeyPair supports '${V4_PUBLIC}', got '${version}'`);
  }
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const seed = rawFromKeyObject(privateKey);
  const pub = rawFromKeyObject(publicKey);
  return { secretKey: Buffer.concat([seed, pub]), publicKey: pub };
}
