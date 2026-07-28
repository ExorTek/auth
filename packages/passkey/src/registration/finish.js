/**
 * `registration.finish` — verify a `PublicKeyCredential` returned
 * from `navigator.credentials.create()`.
 *
 * Steps (WebAuthn L3 §7.1):
 *   1. base64url-decode the response fields
 *   2. consume the challenge token (single-use)
 *   3. parse clientDataJSON, check type / challenge / origin
 *   4. parse attestationObject, split into fmt / authData / attStmt
 *   5. verify RP ID hash (support related origins)
 *   6. enforce flag policy (UP always, plus caller's dials)
 *   7. dispatch on `fmt`, verify attestation
 *   8. compile the credential record for storage
 */

import { createHash } from 'node:crypto';
import { base64url } from '@exortek/crypto/encode';
import { decode } from '../cbor/decode.js';
import { parseAuthData } from '../webauthn/authData.js';
import { parseClientData } from '../webauthn/clientData.js';
import { matchesOrigin } from '../webauthn/originCheck.js';
import { matchRpId } from '../webauthn/rpIdMatch.js';
import { enforceFlags, deviceTypeFromFlags } from '../webauthn/flags.js';
import { readClientExtensionResults, readAuthenticatorExtensions } from '../webauthn/extensions.js';
import { importCoseKey, DEFAULT_SUPPORTED_ALGORITHMS } from '../cose/key.js';
import { consumePasskeyChallenge } from '../internal/challenge.js';
import { getVerifier } from '../attestation/index.js';
import {
  throwInvalidArgument,
  throwClientDataInvalid,
  throwOriginMismatch,
  throwRpIdMismatch,
  throwAuthDataInvalid,
  throwUnsupportedAlgorithm,
} from '../errors.js';

function decodeB64uField(value, field) {
  if (typeof value !== 'string' || value.length === 0) {
    throwInvalidArgument(`registration.finish: response.${field} must be a base64url string`);
  }
  try {
    return new Uint8Array(base64url.decode(value));
  } catch (err) {
    throwInvalidArgument(`registration.finish: response.${field} is not valid base64url (${err.message})`);
  }
}

/**
 * @param {object} params
 * @param {object} params.response
 *   The `PublicKeyCredential` shape the browser produced, with
 *   base64url-encoded fields (JSON-transport form):
 *     { id, rawId, type: 'public-key',
 *       response: { clientDataJSON, attestationObject, transports? },
 *       clientExtensionResults? }
 * @param {string} params.challengeToken
 * @param {string | string[]} params.expectedRpId
 * @param {string | string[] | RegExp} params.expectedOrigin
 * @param {string | Buffer} params.challengeSecret
 * @param {import('@exortek/challenge').IncrStore} params.challengeStore
 * @param {string} [params.expectedUserId]
 * @param {boolean} [params.requireUserVerification=true]
 * @param {boolean} [params.requireBackupEligible=false]
 * @param {boolean} [params.requireBackedUp=false]
 * @param {number[]} [params.supportedAlgorithms]
 * @param {Record<string, Array<unknown>>} [params.trustAnchors]
 *   Per-format trust anchor arrays; each entry is a certificate
 *   accepted by `x509/chain.toCertificate` (PEM string / DER / X509).
 * @param {string} [params.challengePrefix]
 * @returns {Promise<{
 *   credential: {
 *     id: string,
 *     idBytes: Uint8Array,
 *     publicKey: import('node:crypto').KeyObject,
 *     publicKeyJwk: Record<string, unknown>,
 *     publicKeyCose: Map<unknown, unknown>,
 *     algorithm: number,
 *     counter: number,
 *     transports?: string[],
 *   },
 *   aaguid: string,
 *   deviceType: 'singleDevice' | 'multiDevice',
 *   backedUp: boolean,
 *   attestation: {
 *     format: string,
 *     trustPath: string,
 *     aaguidExtensionOk?: boolean,
 *     certChain?: import('node:crypto').X509Certificate[],
 *   },
 *   extensionResults: { client: object, authenticator: object },
 *   rpId: string,
 * }>}
 */
export async function finish(params) {
  if (!params || typeof params !== 'object') {
    throwInvalidArgument('registration.finish: options object required');
  }
  const {
    response,
    challengeToken,
    expectedRpId,
    expectedOrigin,
    challengeSecret,
    challengeStore,
    expectedUserId,
    requireUserVerification = true,
    requireBackupEligible = false,
    requireBackedUp = false,
    supportedAlgorithms = DEFAULT_SUPPORTED_ALGORITHMS,
    trustAnchors = {},
    challengePrefix,
  } = params;

  if (!response || typeof response !== 'object' || !response.response) {
    throwInvalidArgument('registration.finish: response must be a WebAuthn PublicKeyCredential-shaped object');
  }
  if (response.type !== undefined && response.type !== 'public-key') {
    throwInvalidArgument(`registration.finish: response.type must be 'public-key' (got "${response.type}")`);
  }
  if (typeof challengeToken !== 'string' || challengeToken.length === 0) {
    throwInvalidArgument('registration.finish: challengeToken is required');
  }
  if (!expectedRpId) {
    throwInvalidArgument('registration.finish: expectedRpId is required');
  }
  if (!expectedOrigin) {
    throwInvalidArgument('registration.finish: expectedOrigin is required');
  }

  const clientDataJSON = decodeB64uField(response.response.clientDataJSON, 'response.clientDataJSON');
  const attestationObjectBytes = decodeB64uField(response.response.attestationObject, 'response.attestationObject');

  // Client data
  let clientData;
  try {
    clientData = parseClientData(clientDataJSON);
  } catch (err) {
    throwClientDataInvalid(`registration.finish: ${err.message}`);
  }
  if (clientData.type !== 'webauthn.create') {
    throwClientDataInvalid(`registration.finish: clientData.type must be "webauthn.create", got "${clientData.type}"`);
  }
  if (!matchesOrigin(clientData.origin, expectedOrigin)) {
    throwOriginMismatch(`registration.finish: origin "${clientData.origin}" not in expectedOrigin`);
  }

  // Consume challenge — verifies signature, TTL, single-use, method
  // + step bindings, plus jti match with clientData.challenge.
  await consumePasskeyChallenge({
    challengeToken,
    challengeBase64UrlFromClient: clientData.challengeBase64Url,
    secret: challengeSecret,
    store: challengeStore,
    step: 'register',
    userId: expectedUserId,
    prefix: challengePrefix,
  });

  // Attestation object
  let attestationObject;
  try {
    attestationObject = decode(attestationObjectBytes);
  } catch (err) {
    throwAuthDataInvalid(`registration.finish: attestationObject CBOR: ${err.message}`);
  }
  if (!(attestationObject instanceof Map)) {
    throwAuthDataInvalid('registration.finish: attestationObject must be a CBOR map');
  }
  const fmt = attestationObject.get('fmt');
  const authDataBytes = attestationObject.get('authData');
  const attStmt = attestationObject.get('attStmt');
  if (typeof fmt !== 'string' || fmt.length === 0) {
    throwAuthDataInvalid('registration.finish: attestationObject.fmt missing or not a string');
  }
  if (!(authDataBytes instanceof Uint8Array)) {
    throwAuthDataInvalid('registration.finish: attestationObject.authData missing or not bytes');
  }
  if (!(attStmt instanceof Map)) {
    throwAuthDataInvalid('registration.finish: attestationObject.attStmt missing or not a CBOR map');
  }

  const authData = parseAuthData(authDataBytes);
  if (!authData.attestedCredentialData) {
    throwAuthDataInvalid('registration.finish: authenticator data has no attested credential data (AT flag not set)');
  }

  // RP ID check
  const rpMatch = matchRpId(authData.rpIdHash, expectedRpId);
  if (!rpMatch) {
    throwRpIdMismatch(`registration.finish: rpIdHash does not match any expected RP ID`);
  }

  // Flag policy — enforceFlags throws PasskeyError with the specific
  // code (USER_VERIFICATION_REQUIRED / BACKUP_ELIGIBLE_REQUIRED / …)
  // so no local translation is needed.
  enforceFlags(authData.flags, { requireUserVerification, requireBackupEligible, requireBackedUp });

  // Algorithm allowlist
  const credAlg = authData.attestedCredentialData.credentialPublicKey.get(3);
  if (!supportedAlgorithms.includes(credAlg)) {
    throwUnsupportedAlgorithm(
      `registration.finish: credential algorithm ${credAlg} is not in supportedAlgorithms [${supportedAlgorithms.join(', ')}]`,
    );
  }

  // Attestation verification
  const clientDataHash = new Uint8Array(createHash('sha256').update(clientDataJSON).digest());
  const verifier = getVerifier(fmt);
  const attestationReport = verifier({
    attStmt,
    authDataBytes,
    clientDataHash,
    attestedCredentialData: authData.attestedCredentialData,
    trustAnchors: trustAnchors[fmt] ?? trustAnchors[fmt.replace(/-/g, '')],
  });

  // Import credential public key so callers get a Node KeyObject
  // ready for signature verify without re-decoding COSE bytes.
  const importedKey = importCoseKey(authData.attestedCredentialData.credentialPublicKey);

  return {
    credential: {
      id: base64url.encode(authData.attestedCredentialData.credentialId),
      idBytes: authData.attestedCredentialData.credentialId,
      publicKey: importedKey.publicKey,
      publicKeyJwk: importedKey.jwk,
      publicKeyCose: authData.attestedCredentialData.credentialPublicKey,
      algorithm: credAlg,
      counter: authData.signCount,
      transports: Array.isArray(response.response.transports) ? response.response.transports : undefined,
    },
    aaguid: authData.attestedCredentialData.aaguidString,
    deviceType: deviceTypeFromFlags(authData.flags),
    backedUp: authData.flags.bs,
    attestation: attestationReport,
    extensionResults: {
      client: readClientExtensionResults(response.clientExtensionResults),
      authenticator: readAuthenticatorExtensions(authData.extensions),
    },
    rpId: rpMatch.matched,
  };
}
