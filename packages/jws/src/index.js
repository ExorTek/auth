/**
 * `@exortek/jws` — JSON Web Signature for Node.js 22+.
 *
 *   - RFC 7515 (JWS core) — compact + JSON serialisation
 *   - RFC 7518 (JWA) — HS / RS / PS / ES / EdDSA
 *   - RFC 7797 — unencoded payload (`b64: false`)
 *   - RFC 8037 — Ed25519 / Ed448
 *   - RFC 8812 — `secp256k1` / ES256K
 *   - RFC 8725 — JWT / JWS best practices we bake in
 *
 * Server-only, zero-dep. Named exports for tree-shaking, plus a `jws`
 * namespace that mirrors the ARCHITECTURE example.
 */

import { sign, signDetached } from './sign.js';
import { verify, verifyDetached } from './verify.js';
import { decode, decodeProtectedHeader } from './decode.js';
import { signJson, verifyJson } from './json.js';
import { JwsError, ErrorCode } from './internal/errors.js';

export { sign, signDetached, verify, verifyDetached, decode, decodeProtectedHeader };
export { signJson, verifyJson };
export { JwsError, ErrorCode };

/**
 * Bundled namespace matching the ARCHITECTURE example.
 */
export const jws = Object.freeze({
  sign,
  signDetached,
  verify,
  verifyDetached,
  decode,
  decodeProtectedHeader,
  signJson,
  verifyJson,
});

/**
 * @typedef {import('./sign.js').SignOptions} SignOptions
 * @typedef {import('./verify.js').VerifyOptions} VerifyOptions
 * @typedef {import('./verify.js').VerifyResult} VerifyResult
 * @typedef {import('./decode.js').DecodedJws} DecodedJws
 * @typedef {import('./json.js').GeneralJws} GeneralJws
 * @typedef {import('./json.js').FlattenedJws} FlattenedJws
 * @typedef {import('./json.js').SignSpec} SignSpec
 * @typedef {import('./internal/keys.js').KeyInput} KeyInput
 * @typedef {import('./internal/resolver.js').KeyResolverFn} KeyResolverFn
 */
