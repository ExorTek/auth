/**
 * Key material normaliser — turn JWK objects, `KeyObject`s, and
 * `Buffer` / `Uint8Array` HMAC secrets into the concrete `KeyObject`
 * shape the algorithms table expects.
 *
 * Enforces per-alg kty compatibility here so alg-confusion attacks
 * surface as a clean {@link ErrorCode.INVALID_KEY} at the key boundary
 * rather than a cryptic Node error deep in `crypto.sign`. Shared with
 * `@exortek/jwt` via `@exortek/shared/normalize-key`; jwt wraps the
 * same core with its own PEM branch (jws deliberately does not accept
 * PEM strings).
 */

import { createKeyNormalizer } from '@exortek/shared/normalize-key';

import { JwsError, ErrorCode } from './errors.js';
import { lookup as lookupAlg } from './algorithms.js';

/**
 * @typedef {import('node:crypto').KeyObject | Buffer | Uint8Array | Record<string, unknown>} KeyInput
 */

const { normalizeKey } = createKeyNormalizer({
  ErrorClass: JwsError,
  ErrorCode,
  lookupAlg,
});

/**
 * Normalise a caller-supplied key into a `KeyObject`.
 *
 * @type {(key: KeyInput, alg: string, direction: 'sign' | 'verify') => Promise<import('node:crypto').KeyObject>}
 */
export { normalizeKey };
