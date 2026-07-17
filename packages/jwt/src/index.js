/**
 * `@exortek/jwt` — JSON Web Token for Node.js 22+.
 *
 *   - RFC 7519 (JWT core) + RFC 8725 (best current practice)
 *   - RFC 9068 (JWT profile for OAuth 2.0 access tokens)
 *   - RFC 7518 (JWA) + RFC 8037 (Ed25519 / Ed448) + RFC 8812 (secp256k1)
 *   - RFC 6749 §10.4 (refresh-token reuse-detection threat model)
 *
 * Server-only, zero-dep. Named exports for tree-shaking, plus a `jwt`
 * namespace mirroring the ARCHITECTURE example.
 */

import { sign } from './sign.js';
import { verify, peek } from './verify.js';
import { decode, decodeProtectedHeader } from './decode.js';
import { JwtError, ErrorCode } from './internal/errors.js';

export { sign, verify, peek, decode, decodeProtectedHeader };
export { JwtError, ErrorCode };

/**
 * Bundled namespace mirroring the ARCHITECTURE example.
 */
export const jwt = Object.freeze({
  sign,
  verify,
  peek,
  decode,
  decodeProtectedHeader,
});

/**
 * @typedef {import('./sign.js').SignOptions} SignOptions
 * @typedef {import('./verify.js').VerifyOptions} VerifyOptions
 * @typedef {import('./verify.js').VerifyResult} VerifyResult
 * @typedef {import('./decode.js').DecodedJwt} DecodedJwt
 * @typedef {import('./claims.js').ClaimsOptions} ClaimsOptions
 * @typedef {import('./internal/keys.js').KeyInput} KeyInput
 * @typedef {import('./internal/resolver.js').KeyResolverFn} KeyResolverFn
 */
