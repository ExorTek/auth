/**
 * `registration.begin` — build a `PublicKeyCredentialCreationOptionsJSON`
 * for the browser to hand to `navigator.credentials.create()`.
 *
 * Returns two things:
 *   - `options`         the JSON dict the RP serves to the client
 *   - `challengeToken`  a signed challenge token the RP must give
 *                       back to `registration.finish` (put it in a
 *                       cookie / server-side session; it carries a
 *                       one-shot binding to userId + method='passkey'
 *                       + step='register')
 */

import { base64url } from '@exortek/crypto/encode';
import { issuePasskeyChallenge } from '../internal/challenge.js';
import { buildRegistrationExtensions } from '../webauthn/extensions.js';
import { DEFAULT_SUPPORTED_ALGORITHMS } from '../cose/key.js';
import { throwInvalidArgument } from '../errors.js';

const HINT_VALUES = new Set(['security-key', 'client-device', 'hybrid']);
const ATTESTATION_VALUES = new Set(['none', 'direct', 'enterprise']);

/**
 * @param {object} params
 * @param {{ id: string, name: string }} params.rp
 * @param {{ id: string, name: string, displayName: string }} params.user
 * @param {string | Buffer} params.challengeSecret
 * @param {import('@exortek/challenge').IncrStore} params.challengeStore
 * @param {object} [params.authenticatorSelection]
 * @param {'none' | 'direct' | 'enterprise'} [params.attestation='none']
 * @param {Array<'security-key' | 'client-device' | 'hybrid'>} [params.hints]
 * @param {number} [params.timeoutMs=60_000]
 * @param {Array<{ id: string | Uint8Array, type?: string, transports?: string[] }>} [params.excludeCredentials]
 * @param {object} [params.extensions]
 * @param {number[]} [params.supportedAlgorithms]
 * @param {string | number} [params.challengeExpiresIn='5m']
 * @param {string} [params.challengePrefix]
 * @returns {Promise<{
 *   options: Record<string, unknown>,
 *   challengeToken: string,
 * }>}
 */
export async function begin(params) {
  if (!params || typeof params !== 'object') {
    throwInvalidArgument('registration.begin: options object required');
  }
  const rp = params.rp;
  const user = params.user;
  if (!rp || typeof rp.id !== 'string' || typeof rp.name !== 'string') {
    throwInvalidArgument('registration.begin: rp.id and rp.name are required strings');
  }
  if (!user || typeof user.id !== 'string' || typeof user.name !== 'string' || typeof user.displayName !== 'string') {
    throwInvalidArgument('registration.begin: user.id / .name / .displayName are required strings');
  }
  if (!params.challengeSecret) {
    throwInvalidArgument('registration.begin: challengeSecret is required');
  }
  if (!params.challengeStore || typeof params.challengeStore.incr !== 'function') {
    throwInvalidArgument('registration.begin: challengeStore (an IncrStore) is required');
  }

  const attestation = params.attestation ?? 'none';
  if (!ATTESTATION_VALUES.has(attestation)) {
    throwInvalidArgument(
      `registration.begin: attestation must be 'none' | 'direct' | 'enterprise' (got "${attestation}")`,
    );
  }

  const hints = params.hints;
  if (hints !== undefined) {
    if (!Array.isArray(hints)) {
      throwInvalidArgument('registration.begin: hints must be an array');
    }
    for (const h of hints) {
      if (!HINT_VALUES.has(h)) {
        throwInvalidArgument(`registration.begin: hint "${h}" is not one of security-key | client-device | hybrid`);
      }
    }
  }

  const timeout = params.timeoutMs ?? 60_000;
  const algorithms = params.supportedAlgorithms ?? DEFAULT_SUPPORTED_ALGORITHMS;
  const extensions = buildRegistrationExtensions(params.extensions ?? {});

  const { challengeToken, challengeBase64Url } = await issuePasskeyChallenge({
    secret: params.challengeSecret,
    store: params.challengeStore,
    step: 'register',
    userId: user.id,
    expiresIn: params.challengeExpiresIn ?? '5m',
    prefix: params.challengePrefix,
  });

  const options = {
    rp: { id: rp.id, name: rp.name },
    user: {
      // WebAuthn expects user.id as an ArrayBuffer serialised to
      // base64url. We take a string in, base64url-encode its UTF-8
      // bytes so it round-trips predictably back at finish time.
      id: base64url.encode(new TextEncoder().encode(user.id)),
      name: user.name,
      displayName: user.displayName,
    },
    challenge: challengeBase64Url,
    pubKeyCredParams: algorithms.map(alg => ({ type: 'public-key', alg })),
    timeout,
    attestation,
    authenticatorSelection: params.authenticatorSelection,
    excludeCredentials: (params.excludeCredentials ?? []).map(c => ({
      type: c.type ?? 'public-key',
      id: c.id instanceof Uint8Array ? base64url.encode(c.id) : c.id,
      transports: c.transports,
    })),
  };
  if (hints !== undefined) {
    options.hints = hints;
  }
  if (Object.keys(extensions).length > 0) {
    options.extensions = extensions;
  }

  return { options, challengeToken };
}
