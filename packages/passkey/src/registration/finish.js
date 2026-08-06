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
import { PasskeyError, ErrorCode } from '../errors.js';
import { isString, isArray, isObject } from '@exortek/shared/predicates';

/**
 * Resolve the per-format options blob a caller supplied via
 * `attestationOptions`. The value at `attestationOptions[fmt]` wins;
 * a hyphen-stripped key (`androidsafetynet` for `android-safetynet`)
 * is accepted as a fallback for callers who prefer a single-word
 * config name. Returns an empty object when nothing matches.
 *
 * Exported for tests — the real code path calls this once per verify.
 *
 * @param {string} fmt
 * @param {Record<string, Record<string, unknown>> | undefined} attestationOptions
 * @returns {Record<string, unknown>}
 */
export function resolveAttestationOptions(fmt, attestationOptions) {
  if (!attestationOptions) {
    return {};
  }
  const fmtNoDash = fmt.replace(/-/g, '');
  return attestationOptions[fmt] ?? attestationOptions[fmtNoDash] ?? {};
}

function decodeB64uField(value, field) {
  if (!isString(value) || value.length === 0) {
    throw new PasskeyError(
      ErrorCode.INVALID_ARGUMENT,
      `registration.finish: response.${field} must be a base64url string`,
    );
  }
  try {
    return new Uint8Array(base64url.decode(value));
  } catch (err) {
    throw new PasskeyError(
      ErrorCode.INVALID_ARGUMENT,
      `registration.finish: response.${field} is not valid base64url (${err.message})`,
    );
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
 * @param {boolean} [params.allowCrossOriginCeremony=false]
 *   Opt in to accepting `clientDataJSON.crossOrigin === true`. Off by
 *   default: WebAuthn L3 §7.1 step 12 lets the RP set policy, and
 *   most deployments should not accept cross-origin registration
 *   ceremonies.
 * @param {number[]} [params.supportedAlgorithms]
 * @param {Record<string, Array<unknown>>} [params.trustAnchors]
 *   Per-format trust anchor arrays; each entry is a certificate
 *   accepted by `x509/chain.toCertificate` (PEM string / DER / X509).
 * @param {Record<string, Record<string, unknown>>} [params.attestationOptions]
 *   Per-format extra options, keyed by format name (same convention as
 *   `trustAnchors`). Passed verbatim to the format's verifier — used
 *   today by `android-safetynet` (`enforceCtsCheck`,
 *   `timestampWindowMs`, `now`); new formats add knobs here without
 *   further signature changes.
 * @param {boolean} [params.requireTrustAnchor=false]
 *   When true, reject a chain-bearing attestation format that resolved
 *   to `trustPath: 'no-anchor'` (i.e. the caller supplied no anchors
 *   for it). Turns the "attestation silently unverified" footgun into
 *   an explicit `ATTESTATION_TRUST_ANCHOR_MISSING`. `none` and packed
 *   self-attestation are unaffected. Leave false for the passkey common
 *   case (`attestation: 'none'`).
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
  if (!isObject(params)) {
    throw new PasskeyError(ErrorCode.INVALID_ARGUMENT, 'registration.finish: options object required');
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
    allowCrossOriginCeremony = false,
    supportedAlgorithms = DEFAULT_SUPPORTED_ALGORITHMS,
    trustAnchors = {},
    attestationOptions = {},
    requireTrustAnchor = false,
    challengePrefix,
  } = params;

  if (!isObject(response) || !response.response) {
    throw new PasskeyError(
      ErrorCode.INVALID_ARGUMENT,
      'registration.finish: response must be a WebAuthn PublicKeyCredential-shaped object',
    );
  }
  if (response.type !== undefined && response.type !== 'public-key') {
    throw new PasskeyError(
      ErrorCode.INVALID_ARGUMENT,
      `registration.finish: response.type must be 'public-key' (got "${response.type}")`,
    );
  }
  // WebAuthn transports `id` as the base64url of `rawId`; a client
  // that sends mismatched values is malformed (SimpleWebAuthn rejects
  // the same way). Only enforced when both are present.
  if (isString(response.id) && isString(response.rawId) && response.id !== response.rawId) {
    throw new PasskeyError(
      ErrorCode.INVALID_ARGUMENT,
      'registration.finish: response.id must equal response.rawId (base64url mismatch)',
    );
  }
  if (!isString(challengeToken) || challengeToken.length === 0) {
    throw new PasskeyError(ErrorCode.INVALID_ARGUMENT, 'registration.finish: challengeToken is required');
  }
  if (!expectedRpId) {
    throw new PasskeyError(ErrorCode.INVALID_ARGUMENT, 'registration.finish: expectedRpId is required');
  }
  if (!expectedOrigin) {
    throw new PasskeyError(ErrorCode.INVALID_ARGUMENT, 'registration.finish: expectedOrigin is required');
  }

  const clientDataJSON = decodeB64uField(response.response.clientDataJSON, 'response.clientDataJSON');
  const attestationObjectBytes = decodeB64uField(response.response.attestationObject, 'response.attestationObject');

  // Client data
  let clientData;
  try {
    clientData = parseClientData(clientDataJSON);
  } catch (err) {
    throw new PasskeyError(ErrorCode.CLIENT_DATA_INVALID, `registration.finish: ${err.message}`);
  }
  if (clientData.type !== 'webauthn.create') {
    throw new PasskeyError(
      ErrorCode.CLIENT_DATA_INVALID,
      `registration.finish: clientData.type must be "webauthn.create", got "${clientData.type}"`,
    );
  }
  if (!matchesOrigin(clientData.origin, expectedOrigin)) {
    throw new PasskeyError(
      ErrorCode.ORIGIN_MISMATCH,
      `registration.finish: origin "${clientData.origin}" not in expectedOrigin`,
    );
  }
  if (clientData.crossOrigin && !allowCrossOriginCeremony) {
    throw new PasskeyError(
      ErrorCode.CLIENT_DATA_INVALID,
      'registration.finish: clientDataJSON.crossOrigin=true — set allowCrossOriginCeremony to accept cross-origin ceremonies',
    );
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
    throw new PasskeyError(ErrorCode.AUTH_DATA_INVALID, `registration.finish: attestationObject CBOR: ${err.message}`);
  }
  if (!(attestationObject instanceof Map)) {
    throw new PasskeyError(ErrorCode.AUTH_DATA_INVALID, 'registration.finish: attestationObject must be a CBOR map');
  }
  const fmt = attestationObject.get('fmt');
  const authDataBytes = attestationObject.get('authData');
  const attStmt = attestationObject.get('attStmt');
  if (!isString(fmt) || fmt.length === 0) {
    throw new PasskeyError(
      ErrorCode.AUTH_DATA_INVALID,
      'registration.finish: attestationObject.fmt missing or not a string',
    );
  }
  if (!(authDataBytes instanceof Uint8Array)) {
    throw new PasskeyError(
      ErrorCode.AUTH_DATA_INVALID,
      'registration.finish: attestationObject.authData missing or not bytes',
    );
  }
  if (!(attStmt instanceof Map)) {
    throw new PasskeyError(
      ErrorCode.AUTH_DATA_INVALID,
      'registration.finish: attestationObject.attStmt missing or not a CBOR map',
    );
  }

  const authData = parseAuthData(authDataBytes);
  if (!authData.attestedCredentialData) {
    throw new PasskeyError(
      ErrorCode.AUTH_DATA_INVALID,
      'registration.finish: authenticator data has no attested credential data (AT flag not set)',
    );
  }

  // RP ID check
  const rpMatch = matchRpId(authData.rpIdHash, expectedRpId);
  if (!rpMatch) {
    throw new PasskeyError(ErrorCode.RP_ID_MISMATCH, `registration.finish: rpIdHash does not match any expected RP ID`);
  }

  // Flag policy — enforceFlags throws PasskeyError with the specific
  // code (USER_VERIFICATION_REQUIRED / BACKUP_ELIGIBLE_REQUIRED / …)
  // so no local translation is needed.
  enforceFlags(authData.flags, { requireUserVerification, requireBackupEligible, requireBackedUp });

  // Algorithm allowlist
  const credAlg = authData.attestedCredentialData.credentialPublicKey.get(3);
  if (!supportedAlgorithms.includes(credAlg)) {
    throw new PasskeyError(
      ErrorCode.UNSUPPORTED_ALGORITHM,
      `registration.finish: credential algorithm ${credAlg} is not in supportedAlgorithms [${supportedAlgorithms.join(', ')}]`,
    );
  }

  // Attestation verification
  const clientDataHash = new Uint8Array(createHash('sha256').update(clientDataJSON).digest());
  const verifier = getVerifier(fmt);
  const fmtNoDash = fmt.replace(/-/g, '');
  const attestationReport = verifier({
    attStmt,
    authDataBytes,
    clientDataHash,
    attestedCredentialData: authData.attestedCredentialData,
    trustAnchors: trustAnchors[fmt] ?? trustAnchors[fmtNoDash],
    ...resolveAttestationOptions(fmt, attestationOptions),
  });

  // Trust-anchor policy. A format that carries a certificate chain
  // (`packed` full, `tpm`, `apple`, `android-key`, `android-safetynet`,
  // `fido-u2f`) reports `trustPath: 'no-anchor'` when the caller did
  // not supply anchors for it — the chain was NOT verified to any root,
  // so the attestation proves nothing about the authenticator's make.
  // `none` (and `packed` self, which reports `'self'`) are exempt: they
  // never had a chain to anchor. Opt in with `requireTrustAnchor` to
  // turn that silent gap into a hard failure.
  if (requireTrustAnchor && fmt !== 'none' && attestationReport.trustPath === 'no-anchor') {
    throw new PasskeyError(
      ErrorCode.ATTESTATION_TRUST_ANCHOR_MISSING,
      `registration.finish: attestation format "${fmt}" was not verified against any trust anchor ` +
        `(pass trustAnchors["${fmt}"], or drop requireTrustAnchor to accept unanchored attestation)`,
    );
  }

  // Import credential public key so callers get a Node KeyObject
  // ready for signature verify without re-decoding COSE bytes.
  let importedKey;
  try {
    importedKey = importCoseKey(authData.attestedCredentialData.credentialPublicKey);
  } catch (err) {
    throw new PasskeyError(
      ErrorCode.PUBLIC_KEY_UNSUPPORTED,
      `registration.finish: credential public key could not be imported (${err.message})`,
    );
  }

  return {
    credential: {
      id: base64url.encode(authData.attestedCredentialData.credentialId),
      idBytes: authData.attestedCredentialData.credentialId,
      publicKey: importedKey.publicKey,
      publicKeyJwk: importedKey.jwk,
      publicKeyCose: authData.attestedCredentialData.credentialPublicKey,
      algorithm: credAlg,
      counter: authData.signCount,
      transports: isArray(response.response.transports) ? response.response.transports : undefined,
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
