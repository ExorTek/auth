/**
 * `authentication.finish` — verify an assertion returned from
 * `navigator.credentials.get()`. Steps (WebAuthn L3 §7.2):
 *
 *   1. base64url-decode response fields
 *   2. consume challenge token
 *   3. parse clientDataJSON (type == "webauthn.get", check origin)
 *   4. parse authenticatorData (rpIdHash + flags + counter,
 *      typically no attestedCredentialData)
 *   5. verify RP ID hash
 *   6. enforce flag policy
 *   7. verify signature over authData || sha256(clientDataJSON)
 *      with the stored credential's public key
 *   8. counter monotonicity check (roll-back detection)
 */

import { createHash, createVerify, verify as verifyRaw } from 'node:crypto';
import { base64url } from '@exortek/crypto/encode';
import { parseAuthData } from '../webauthn/authData.js';
import { parseClientData } from '../webauthn/clientData.js';
import { matchesOrigin } from '../webauthn/originCheck.js';
import { matchRpId } from '../webauthn/rpIdMatch.js';
import { enforceFlags, deviceTypeFromFlags } from '../webauthn/flags.js';
import { readClientExtensionResults, readAuthenticatorExtensions } from '../webauthn/extensions.js';
import { importCoseKey, algorithmForId } from '../cose/key.js';
import { consumePasskeyChallenge } from '../internal/challenge.js';
import { concat } from '../internal/bytes.js';
import { PasskeyError, ErrorCode } from '../errors.js';
import { isString, isObject } from '@exortek/shared/predicates';

function decodeB64uField(value, field) {
  if (!isString(value) || value.length === 0) {
    throw new PasskeyError(
      ErrorCode.INVALID_ARGUMENT,
      `authentication.finish: response.${field} must be a base64url string`,
    );
  }
  try {
    return new Uint8Array(base64url.decode(value));
  } catch (err) {
    throw new PasskeyError(
      ErrorCode.INVALID_ARGUMENT,
      `authentication.finish: response.${field} is not valid base64url (${err.message})`,
    );
  }
}

function importCredentialKey(credential) {
  // The RP stores whatever we handed back at register-time —
  // typically the COSE Map. Accept either the raw COSE map or a
  // pre-imported KeyObject (via credential.publicKey).
  if (isObject(credential.publicKey) && 'export' in credential.publicKey) {
    // Node's KeyObject exposes an `export` method — treat as ready.
    return { publicKey: credential.publicKey, algorithm: credential.algorithm };
  }
  if (credential.publicKeyCose instanceof Map) {
    let imported;
    try {
      imported = importCoseKey(credential.publicKeyCose);
    } catch (err) {
      throw new PasskeyError(
        ErrorCode.PUBLIC_KEY_UNSUPPORTED,
        `authentication.finish: stored credential public key is unusable (${err.message})`,
      );
    }
    return { publicKey: imported.publicKey, algorithm: imported.algorithm };
  }
  throw new PasskeyError(
    ErrorCode.INVALID_ARGUMENT,
    'authentication.finish: credential must expose either `publicKey` (Node KeyObject) or `publicKeyCose` (COSE Map)',
  );
}

/**
 * @param {object} params
 * @param {object} params.response
 * @param {string} params.challengeToken
 * @param {string | string[]} params.expectedRpId
 * @param {string | string[] | RegExp} params.expectedOrigin
 * @param {string | Buffer} params.challengeSecret
 * @param {import('@exortek/challenge').IncrStore} params.challengeStore
 * @param {{
 *   publicKey?: import('node:crypto').KeyObject,
 *   publicKeyCose?: Map<unknown, unknown>,
 *   algorithm?: number,
 *   counter: number,
 *   transports?: string[],
 * }} params.credential
 * @param {string} [params.expectedUserId]
 * @param {boolean} [params.requireUserVerification=true]
 * @param {boolean} [params.requireBackupEligible=false]
 * @param {boolean} [params.requireBackedUp=false]
 * @param {boolean} [params.allowCrossOriginCeremony=false]
 *   Opt in to accepting `clientDataJSON.crossOrigin === true`. Off by
 *   default, matching registration.finish — the assertion is normally
 *   invoked from the top-level RP origin.
 * @param {string} [params.challengePrefix]
 * @returns {Promise<{
 *   verified: true,
 *   newCounter: number,
 *   credentialId: string,
 *   userHandle: Uint8Array | null,
 *   deviceType: 'singleDevice' | 'multiDevice',
 *   backedUp: boolean,
 *   extensionResults: { client: object, authenticator: object },
 *   rpId: string,
 * }>}
 */
export async function finish(params) {
  if (!isObject(params)) {
    throw new PasskeyError(ErrorCode.INVALID_ARGUMENT, 'authentication.finish: options object required');
  }
  const {
    response,
    challengeToken,
    expectedRpId,
    expectedOrigin,
    challengeSecret,
    challengeStore,
    credential,
    expectedUserId,
    requireUserVerification = true,
    requireBackupEligible = false,
    requireBackedUp = false,
    allowCrossOriginCeremony = false,
    challengePrefix,
  } = params;

  if (!isObject(response) || !response.response) {
    throw new PasskeyError(
      ErrorCode.INVALID_ARGUMENT,
      'authentication.finish: response must be a WebAuthn PublicKeyCredential-shaped object',
    );
  }
  if (response.type !== undefined && response.type !== 'public-key') {
    throw new PasskeyError(
      ErrorCode.INVALID_ARGUMENT,
      `authentication.finish: response.type must be 'public-key' (got "${response.type}")`,
    );
  }
  // `id` is the base64url of `rawId`; reject a client that disagrees
  // with itself (matches SimpleWebAuthn). Only when both are present.
  if (isString(response.id) && isString(response.rawId) && response.id !== response.rawId) {
    throw new PasskeyError(
      ErrorCode.INVALID_ARGUMENT,
      'authentication.finish: response.id must equal response.rawId (base64url mismatch)',
    );
  }
  if (!challengeToken) {
    throw new PasskeyError(ErrorCode.INVALID_ARGUMENT, 'authentication.finish: challengeToken is required');
  }
  if (!isObject(credential) || typeof credential.counter !== 'number') {
    throw new PasskeyError(
      ErrorCode.INVALID_ARGUMENT,
      'authentication.finish: credential must include the stored counter (number)',
    );
  }

  const clientDataJSON = decodeB64uField(response.response.clientDataJSON, 'response.clientDataJSON');
  const authDataBytes = decodeB64uField(response.response.authenticatorData, 'response.authenticatorData');
  const signature = decodeB64uField(response.response.signature, 'response.signature');
  const userHandle = response.response.userHandle
    ? decodeB64uField(response.response.userHandle, 'response.userHandle')
    : null;

  let clientData;
  try {
    clientData = parseClientData(clientDataJSON);
  } catch (err) {
    throw new PasskeyError(ErrorCode.CLIENT_DATA_INVALID, `authentication.finish: ${err.message}`);
  }
  if (clientData.type !== 'webauthn.get') {
    throw new PasskeyError(
      ErrorCode.CLIENT_DATA_INVALID,
      `authentication.finish: clientData.type must be "webauthn.get" (got "${clientData.type}")`,
    );
  }
  if (!matchesOrigin(clientData.origin, expectedOrigin)) {
    throw new PasskeyError(
      ErrorCode.ORIGIN_MISMATCH,
      `authentication.finish: origin "${clientData.origin}" not in expectedOrigin`,
    );
  }
  if (clientData.crossOrigin && !allowCrossOriginCeremony) {
    throw new PasskeyError(
      ErrorCode.CLIENT_DATA_INVALID,
      'authentication.finish: clientDataJSON.crossOrigin=true — set allowCrossOriginCeremony to accept cross-origin ceremonies',
    );
  }

  await consumePasskeyChallenge({
    challengeToken,
    challengeBase64UrlFromClient: clientData.challengeBase64Url,
    secret: challengeSecret,
    store: challengeStore,
    step: 'authenticate',
    userId: expectedUserId,
    prefix: challengePrefix,
  });

  const authData = parseAuthData(authDataBytes);

  const rpMatch = matchRpId(authData.rpIdHash, expectedRpId);
  if (!rpMatch) {
    throw new PasskeyError(
      ErrorCode.RP_ID_MISMATCH,
      'authentication.finish: rpIdHash does not match any expected RP ID',
    );
  }

  enforceFlags(authData.flags, { requireUserVerification, requireBackupEligible, requireBackedUp });

  // Signed input: authData || SHA-256(clientDataJSON)  — WebAuthn L3 §7.2 step 20.
  const clientDataHash = new Uint8Array(createHash('sha256').update(clientDataJSON).digest());
  const signedInput = concat(authDataBytes, clientDataHash);

  const { publicKey, algorithm } = importCredentialKey(credential);
  const algParams = algorithmForId(algorithm);

  let ok;
  if (algParams.nodeAlgorithm === null) {
    ok = verifyRaw(null, signedInput, publicKey, signature);
  } else {
    const v = createVerify(algParams.nodeAlgorithm);
    v.update(signedInput);
    ok = v.verify({ key: publicKey, ...algParams.verifyOptions }, signature);
  }
  if (!ok) {
    throw new PasskeyError(
      ErrorCode.SIGNATURE_INVALID,
      'authentication.finish: signature does not verify against stored credential public key',
    );
  }

  // Counter monotonicity (WebAuthn L3 §7.2 step 21). Some
  // authenticators keep counter at 0 forever — that's allowed only
  // when the STORED counter is also 0; anything else must strictly
  // increase.
  if (authData.signCount === 0 && credential.counter === 0) {
    // OK — permitted no-counter case.
  } else if (authData.signCount <= credential.counter) {
    throw new PasskeyError(
      ErrorCode.COUNTER_ROLLBACK,
      `authentication.finish: counter did not increase (stored=${credential.counter}, received=${authData.signCount}) — possible cloned authenticator`,
    );
  }

  return {
    verified: true,
    newCounter: authData.signCount,
    credentialId: response.id ?? response.rawId,
    userHandle,
    deviceType: deviceTypeFromFlags(authData.flags),
    backedUp: authData.flags.bs,
    extensionResults: {
      client: readClientExtensionResults(response.clientExtensionResults),
      authenticator: readAuthenticatorExtensions(authData.extensions),
    },
    rpId: rpMatch.matched,
  };
}
