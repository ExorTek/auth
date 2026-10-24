/**
 * Key generation for the two v4 purposes. Both return typed `PasetoKey`s
 * (see `key.js`); `.export()` gives the raw wire form.
 *
 *   - `generateKey()`      → v4 `local` key (32 bytes)
 *   - `generateKeyPair()`  → { secretKey: v4 `secret` (64B seed ‖ public),
 *                              publicKey: v4 `public` (32B) }
 */

import { randomBytes, generateKeyPairSync } from 'node:crypto';

import { rawFromKeyObject } from './internal/keys.js';
import { makeKey } from './key.js';
import { V4_LOCAL, V4_PUBLIC } from './internal/versions.js';
import { PasetoError, ErrorCode } from './internal/errors.js';

/**
 * Generate a symmetric key for `v4.local`.
 * @param {string} [version='v4.local']
 * @returns {import('./key.js').PasetoKey}
 */
export function generateKey(version = V4_LOCAL) {
  if (version !== V4_LOCAL) {
    throw new PasetoError(ErrorCode.UNSUPPORTED_VERSION, `generateKey supports '${V4_LOCAL}', got '${version}'`);
  }
  return makeKey('local', randomBytes(32));
}

/**
 * Generate an Ed25519 key pair for `v4.public`, in raw wire form.
 * @param {string} [version='v4.public']
 * @returns {{ secretKey: import('./key.js').PasetoKey, publicKey: import('./key.js').PasetoKey }}
 */
export function generateKeyPair(version = V4_PUBLIC) {
  if (version !== V4_PUBLIC) {
    throw new PasetoError(ErrorCode.UNSUPPORTED_VERSION, `generateKeyPair supports '${V4_PUBLIC}', got '${version}'`);
  }
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const seed = rawFromKeyObject(privateKey);
  const pub = rawFromKeyObject(publicKey);
  return { secretKey: makeKey('secret', Buffer.concat([seed, pub])), publicKey: makeKey('public', pub) };
}
