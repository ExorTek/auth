/**
 * `@exortek/jwks` — JSON Web Key Set (RFC 7517 §5). Zero-dependency,
 * `node:crypto` only (plus `@exortek/jwk` for key primitives).
 *
 * ```js
 * // Namespace style
 * import { jwks } from '@exortek/jwks'
 * const keySet = await jwks.create([{ alg: 'ES256', kid: 'sig-2024' }])
 * const remote = jwks.remote('https://example.com/.well-known/jwks.json')
 *
 * // Named imports
 * import { createLocalKeySet } from '@exortek/jwks/local'
 * import { createRemoteJWKS } from '@exortek/jwks/remote'
 * ```
 */

import { createLocalKeySet } from './local.js';
import { createRemoteJWKS } from './remote.js';
import { JwksError, ErrorCode } from './errors.js';

const jwks = Object.freeze({
  create: createLocalKeySet,
  remote: createRemoteJWKS,
});

export { jwks, createLocalKeySet, createRemoteJWKS, JwksError, ErrorCode };
