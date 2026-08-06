/**
 * `authentication.begin` — build a
 * `PublicKeyCredentialRequestOptionsJSON` for
 * `navigator.credentials.get()`.
 */

import { base64url } from '@exortek/crypto/encode';
import { issuePasskeyChallenge } from '../internal/challenge.js';
import { buildAuthenticationExtensions } from '../webauthn/extensions.js';
import { PasskeyError, ErrorCode } from '../errors.js';

const HINT_VALUES = new Set(['security-key', 'client-device', 'hybrid']);
const UV_VALUES = new Set(['required', 'preferred', 'discouraged']);

/**
 * @param {object} params
 * @param {string | string[]} params.rpId
 * @param {string | Buffer} params.challengeSecret
 * @param {import('@exortek/challenge').IncrStore} params.challengeStore
 * @param {Array<{ id: string | Uint8Array, type?: string, transports?: string[] }>} [params.allowCredentials]
 * @param {'required' | 'preferred' | 'discouraged'} [params.userVerification]
 * @param {Array<'security-key' | 'client-device' | 'hybrid'>} [params.hints]
 * @param {number} [params.timeoutMs=60_000]
 * @param {object} [params.extensions]
 * @param {boolean} [params.conditional]
 * @param {string} [params.userId]
 * @param {string | number} [params.challengeExpiresIn='5m']
 * @param {string} [params.challengePrefix]
 * @returns {Promise<{
 *   options: Record<string, unknown>,
 *   challengeToken: string,
 * }>}
 */
export async function begin(params) {
  if (!params || typeof params !== 'object') {
    throw new PasskeyError(ErrorCode.INVALID_ARGUMENT, 'authentication.begin: options object required');
  }
  const rpId = params.rpId;
  if (!rpId || (typeof rpId !== 'string' && !Array.isArray(rpId))) {
    throw new PasskeyError(ErrorCode.INVALID_ARGUMENT, 'authentication.begin: rpId (string or string[]) is required');
  }
  if (!params.challengeSecret) {
    throw new PasskeyError(ErrorCode.INVALID_ARGUMENT, 'authentication.begin: challengeSecret is required');
  }
  if (!params.challengeStore || typeof params.challengeStore.incr !== 'function') {
    throw new PasskeyError(
      ErrorCode.INVALID_ARGUMENT,
      'authentication.begin: challengeStore (an IncrStore) is required',
    );
  }
  if (params.userVerification !== undefined && !UV_VALUES.has(params.userVerification)) {
    throw new PasskeyError(
      ErrorCode.INVALID_ARGUMENT,
      `authentication.begin: userVerification must be 'required' | 'preferred' | 'discouraged' (got "${params.userVerification}")`,
    );
  }
  if (params.hints !== undefined) {
    if (!Array.isArray(params.hints)) {
      throw new PasskeyError(ErrorCode.INVALID_ARGUMENT, 'authentication.begin: hints must be an array');
    }
    for (const h of params.hints) {
      if (!HINT_VALUES.has(h)) {
        throw new PasskeyError(
          ErrorCode.INVALID_ARGUMENT,
          `authentication.begin: hint "${h}" not one of security-key | client-device | hybrid`,
        );
      }
    }
  }

  const primaryRpId = Array.isArray(rpId) ? rpId[0] : rpId;
  const timeout = params.timeoutMs ?? 60_000;
  const extensions = buildAuthenticationExtensions(params.extensions ?? {});

  const { challengeToken, challengeBase64Url } = await issuePasskeyChallenge({
    secret: params.challengeSecret,
    store: params.challengeStore,
    step: 'authenticate',
    userId: params.userId,
    expiresIn: params.challengeExpiresIn ?? '5m',
    prefix: params.challengePrefix,
  });

  const options = {
    challenge: challengeBase64Url,
    timeout,
    rpId: primaryRpId,
    allowCredentials: (params.allowCredentials ?? []).map(c => ({
      type: c.type ?? 'public-key',
      id: c.id instanceof Uint8Array ? base64url.encode(c.id) : c.id,
      transports: c.transports,
    })),
    userVerification: params.userVerification ?? 'preferred',
  };
  if (params.hints !== undefined) {
    options.hints = params.hints;
  }
  if (Object.keys(extensions).length > 0) {
    options.extensions = extensions;
  }
  if (params.conditional === true) {
    options.mediation = 'conditional';
  }

  return { options, challengeToken };
}
