/**
 * JWK Thumbprint (RFC 7638) and JWK Thumbprint URI (RFC 9278).
 *
 * A thumbprint is a stable, kty-defined digest over the JWK's required
 * members. It gives every key a canonical identifier that is independent
 * of `kid` / whitespace / member order — perfect for equality checks and
 * as a `kid` fallback.
 */

import { createHash } from 'node:crypto';

import { JwkError, ErrorCode } from './internal/errors.js';
import { canonicalise } from './internal/canonical.js';
import { encode as b64uEncode } from './internal/base64url.js';

/**
 * @typedef {'sha256' | 'sha384' | 'sha512'} ThumbprintDigest
 */

const DIGEST_URI_LABEL = /** @type {const} */ ({
  sha256: 'sha-256',
  sha384: 'sha-384',
  sha512: 'sha-512',
});

/**
 * Compute the JWK thumbprint per RFC 7638 §3, encoded as base64url.
 *
 * @param {object} jwk
 * @param {ThumbprintDigest} [digest='sha256']
 * @returns {Promise<string>}
 */
export async function thumbprint(jwk, digest = 'sha256') {
  _assertDigest(digest);
  const bytes = canonicalise(jwk);
  const hash = createHash(digest).update(bytes).digest();
  return b64uEncode(hash);
}

/**
 * Compute the JWK Thumbprint URI per RFC 9278 §3:
 * `urn:ietf:params:oauth:jwk-thumbprint:sha-256:<thumbprint>`.
 *
 * @param {object} jwk
 * @param {ThumbprintDigest} [digest='sha256']
 * @returns {Promise<string>}
 */
export async function thumbprintURI(jwk, digest = 'sha256') {
  _assertDigest(digest);
  const tp = await thumbprint(jwk, digest);
  return `urn:ietf:params:oauth:jwk-thumbprint:${DIGEST_URI_LABEL[digest]}:${tp}`;
}

/**
 * Semantic-equality check via thumbprint. Two JWKs match when their
 * required members (per kty) produce the same digest, regardless of
 * `kid` / `use` / `alg` decoration — even when one is the private form
 * and the other the public projection.
 *
 * @param {object} a
 * @param {object} b
 * @param {ThumbprintDigest} [digest='sha256']
 * @returns {Promise<boolean>}
 */
export async function matches(a, b, digest = 'sha256') {
  const [ta, tb] = await Promise.all([thumbprint(a, digest), thumbprint(b, digest)]);
  return ta === tb;
}

/**
 * @param {string} digest
 */
function _assertDigest(digest) {
  if (!(digest in DIGEST_URI_LABEL)) {
    throw new JwkError(
      ErrorCode.UNSUPPORTED_ALGORITHM,
      `thumbprint: unsupported digest ${JSON.stringify(digest)} — expected one of ${Object.keys(DIGEST_URI_LABEL).join(', ')}`,
    );
  }
}
