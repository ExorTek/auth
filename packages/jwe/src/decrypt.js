/**
 * Compact JWE consumption — `decrypt(token, key, options)` (RFC 7516 §5.2).
 *
 * SCAFFOLD: the signature and options contract are frozen here. The
 * `alg` + `enc` allowlists are **mandatory** (same posture as
 * `@exortek/jws` verify), so the contract advertises them now; the
 * unwrap / AEAD-decrypt core lands in the next implementation commit.
 */

import { JweError, ErrorCode } from './internal/errors.js';

/**
 * @typedef {import('node:crypto').KeyObject | Buffer | Uint8Array | Record<string, unknown>} KeyInput
 */

/**
 * @typedef {Object} DecryptOptions
 * @property {string[]} alg  Allowlist of accepted key-management algorithms
 *   (REQUIRED, non-empty). A token whose `alg` is absent throws
 *   {@link ErrorCode.ALGORITHM_MISMATCH}.
 * @property {string[]} enc  Allowlist of accepted content-encryption
 *   algorithms (REQUIRED, non-empty).
 * @property {number} [maxTokenSize=8192]  Reject larger tokens with
 *   {@link ErrorCode.TOKEN_TOO_LARGE}.
 * @property {string[]} [knownCriticalHeaders]  `crit` params this caller
 *   understands.
 */

/**
 * @typedef {Object} DecryptResult
 * @property {Record<string, unknown>} protectedHeader
 * @property {unknown} payload  Parsed JSON when the plaintext is JSON, else
 *   the raw plaintext `Buffer`.
 */

/**
 * Decrypt a compact JWE.
 *
 * @param {string} _token
 * @param {KeyInput} _key
 * @param {DecryptOptions} _options
 * @returns {Promise<DecryptResult>}
 */
export async function decrypt(_token, _key, _options) {
  throw new JweError(
    ErrorCode.NOT_IMPLEMENTED,
    'jwe.decrypt is not implemented yet — the decryption core lands in a follow-up commit.',
  );
}
