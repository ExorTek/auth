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
import {
  throwInvalidArgument,
  throwClientDataInvalid,
  throwOriginMismatch,
  throwRpIdMismatch,
  throwAuthDataInvalid,
  throwSignatureInvalid,
  throwCounterRollback,
} from '../errors.js';

function decodeB64uField(value, field) {
  if (typeof value !== 'string' || value.length === 0) {
    throwInvalidArgument(`authentication.finish: response.${field} must be a base64url string`);
  }
  try {
    return new Uint8Array(base64url.decode(value));
  } catch (err) {
    throwInvalidArgument(`authentication.finish: response.${field} is not valid base64url (${err.message})`);
  }
  return undefined;
}

function importCredentialKey(credential) {
  // The RP stores whatever we handed back at register-time —
  // typically the COSE Map. Accept either the raw COSE map or a
  // pre-imported KeyObject (via credential.publicKey).
  if (credential.publicKey && typeof credential.publicKey === 'object' && 'export' in credential.publicKey) {
    // Node's KeyObject exposes an `export` method — treat as ready.
    return { publicKey: credential.publicKey, algorithm: credential.algorithm };
  }
  if (credential.publicKeyCose instanceof Map) {
    const imported = importCoseKey(credential.publicKeyCose);
    return { publicKey: imported.publicKey, algorithm: imported.algorithm };
  }
  throwInvalidArgument(
    'authentication.finish: credential must expose either `publicKey` (Node KeyObject) or `publicKeyCose` (COSE Map)',
  );
  return undefined;
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
 * @param {boolean} [params.requireBackedUp=false]
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
  if (!params || typeof params !== 'object') {
    throwInvalidArgument('authentication.finish: options object required');
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
    requireBackedUp = false,
    challengePrefix,
  } = params;

  if (!response || typeof response !== 'object' || !response.response) {
    throwInvalidArgument('authentication.finish: response must be a WebAuthn PublicKeyCredential-shaped object');
  }
  if (response.type !== undefined && response.type !== 'public-key') {
    throwInvalidArgument(`authentication.finish: response.type must be 'public-key' (got "${response.type}")`);
  }
  if (!challengeToken) {
    throwInvalidArgument('authentication.finish: challengeToken is required');
  }
  if (!credential || typeof credential !== 'object' || typeof credential.counter !== 'number') {
    throwInvalidArgument('authentication.finish: credential must include the stored counter (number)');
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
    throwClientDataInvalid(`authentication.finish: ${err.message}`);
  }
  if (clientData.type !== 'webauthn.get') {
    throwClientDataInvalid(`authentication.finish: clientData.type must be "webauthn.get" (got "${clientData.type}")`);
  }
  if (!matchesOrigin(clientData.origin, expectedOrigin)) {
    throwOriginMismatch(`authentication.finish: origin "${clientData.origin}" not in expectedOrigin`);
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
    throwRpIdMismatch('authentication.finish: rpIdHash does not match any expected RP ID');
  }

  try {
    enforceFlags(authData.flags, { requireUserVerification, requireBackedUp });
  } catch (err) {
    throwAuthDataInvalid(`authentication.finish: ${err.message}`);
  }

  // Signed input: authData || SHA-256(clientDataJSON)  — WebAuthn L3 §7.2 step 20.
  const clientDataHash = new Uint8Array(createHash('sha256').update(clientDataJSON).digest());
  const signedInput = new Uint8Array(authDataBytes.byteLength + clientDataHash.byteLength);
  signedInput.set(authDataBytes, 0);
  signedInput.set(clientDataHash, authDataBytes.byteLength);

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
    throwSignatureInvalid('authentication.finish: signature does not verify against stored credential public key');
  }

  // Counter monotonicity (WebAuthn L3 §7.2 step 21). Some
  // authenticators keep counter at 0 forever — that's allowed only
  // when the STORED counter is also 0; anything else must strictly
  // increase.
  if (authData.signCount === 0 && credential.counter === 0) {
    // OK — permitted no-counter case.
  } else if (authData.signCount <= credential.counter) {
    throwCounterRollback(
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
