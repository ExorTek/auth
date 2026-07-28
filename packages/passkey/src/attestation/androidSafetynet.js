/**
 * "android-safetynet" attestation (WebAuthn L3 §8.5).
 *
 * Google's SafetyNet Attestation API — historically the way stock
 * Android reported hardware integrity to the RP. Google deprecated
 * SafetyNet in 2023 in favour of Play Integrity, but old
 * authenticators still ship this and the WebAuthn spec still
 * recognises the format.
 *
 * Wire shape:
 *   attStmt = { ver: string, response: Uint8Array }
 *   response is a compact JWS: `<header>.<payload>.<signature>`
 *     header.x5c   — attestation cert chain (leaf CN "attest.android.com")
 *     header.alg   — always "RS256"
 *     payload:
 *       nonce               base64(SHA-256(authData || clientDataHash))
 *       ctsProfileMatch     bool  — CTS/Play Protect integrity
 *       basicIntegrity      bool
 *       timestampMs         number
 *       apkPackageName / apkDigestSha256 / apkCertificateDigestSha256
 *
 * Verify:
 *   1. Split JWS, base64url-decode segments, JSON-parse header +
 *      payload.
 *   2. Reject unless header.alg === "RS256".
 *   3. Verify the signature (RSA-SHA256) using x5c[0].publicKey over
 *      the ASCII bytes `<header_b64>.<payload_b64>` (per JWS §5.2).
 *   4. Assert payload.nonce base64 === SHA-256(authData || clientDataHash).
 *   5. Assert leaf CN === "attest.android.com".
 *   6. Assert `basicIntegrity === true`; if `enforceCtsCheck` is
 *      true (default), also assert `ctsProfileMatch === true`
 *      (matching @simplewebauthn v13.2's `attestationSafetyNetEnforceCTSCheck`
 *      knob).
 *   7. Assert `timestampMs` inside the allowed window.
 *   8. Verify chain against RP-supplied anchors (Google hardware
 *      root in prod).
 */

import { createHash, createVerify, X509Certificate } from 'node:crypto';
import { base64url } from '@exortek/crypto/encode';
import { verifyChain, toCertificates } from '../x509/chain.js';
import { throwAttestationInvalid, throwAttestationTrustAnchorMissing, throwSignatureInvalid } from '../errors.js';

const LEAF_CN = 'attest.android.com';
const DEFAULT_TIMESTAMP_WINDOW_MS = 5 * 60_000; // 5 minutes either side

function decodeBase64UrlToUint8(str, label) {
  try {
    return new Uint8Array(base64url.decode(str));
  } catch (err) {
    throwAttestationInvalid(`android-safetynet: ${label} is not valid base64url (${err.message})`);
  }
  return undefined;
}

function decodeJsonSegment(str, label) {
  const bytes = decodeBase64UrlToUint8(str, label);
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch (err) {
    throwAttestationInvalid(`android-safetynet: ${label} is not valid UTF-8 (${err.message})`);
  }
  try {
    return JSON.parse(text);
  } catch (err) {
    throwAttestationInvalid(`android-safetynet: ${label} is not valid JSON (${err.message})`);
  }
  return undefined;
}

/**
 * @param {object} params
 * @param {Map<unknown, unknown>} params.attStmt
 * @param {Uint8Array} params.authDataBytes
 * @param {Uint8Array} params.clientDataHash
 * @param {Array<unknown>} [params.trustAnchors]
 * @param {boolean} [params.enforceCtsCheck=true]  matches
 *   `attestationSafetyNetEnforceCTSCheck` from `@simplewebauthn/server` v13.2
 * @param {number} [params.timestampWindowMs]  ± tolerance
 * @param {number} [params.now]  epoch ms; defaults to `Date.now()`
 * @returns {{
 *   format: 'android-safetynet',
 *   trustPath: 'trust-anchor' | 'no-anchor',
 *   certChain: import('node:crypto').X509Certificate[],
 *   ctsProfileMatch: boolean,
 *   basicIntegrity: boolean,
 *   timestampMs: number,
 * }}
 */
export function verifyAndroidSafetynet(params) {
  const {
    attStmt,
    authDataBytes,
    clientDataHash,
    trustAnchors,
    enforceCtsCheck = true,
    timestampWindowMs = DEFAULT_TIMESTAMP_WINDOW_MS,
    now = Date.now(),
  } = params;

  if (!(attStmt instanceof Map)) {
    throwAttestationInvalid('android-safetynet: attStmt is not a CBOR map');
  }
  const ver = attStmt.get('ver');
  const response = attStmt.get('response');
  if (typeof ver !== 'string' || ver.length === 0) {
    throwAttestationInvalid('android-safetynet: attStmt.ver missing or not a string');
  }
  if (!(response instanceof Uint8Array) || response.byteLength === 0) {
    throwAttestationInvalid('android-safetynet: attStmt.response missing or not a byte string');
  }

  const responseStr = new TextDecoder('utf-8', { fatal: true }).decode(response);
  const segments = responseStr.split('.');
  if (segments.length !== 3) {
    throwAttestationInvalid('android-safetynet: response must be a compact JWS with three segments');
  }
  const [headerB64, payloadB64, signatureB64] = segments;
  const header = decodeJsonSegment(headerB64, 'JWS header');
  const payload = decodeJsonSegment(payloadB64, 'JWS payload');
  const signature = decodeBase64UrlToUint8(signatureB64, 'JWS signature');

  if (header.alg !== 'RS256') {
    throwAttestationInvalid(`android-safetynet: header.alg must be "RS256" (got "${header.alg}")`);
  }
  if (!Array.isArray(header.x5c) || header.x5c.length === 0) {
    throwAttestationInvalid('android-safetynet: header.x5c must be a non-empty cert array');
  }

  // Chain — header.x5c is an array of base64-encoded DER certs (RFC 7515 §4.1.6).
  const chain = header.x5c.map((b64, i) => {
    try {
      return new X509Certificate(Buffer.from(b64, 'base64'));
    } catch (err) {
      throwAttestationInvalid(`android-safetynet: header.x5c[${i}] not a valid certificate (${err.message})`);
      return null;
    }
  });
  const leaf = chain[0];

  // Signature verify.
  const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const v = createVerify('RSA-SHA256');
  v.update(signingInput);
  if (!v.verify(leaf.publicKey, signature)) {
    throwSignatureInvalid('android-safetynet: JWS signature does not verify against leaf certificate');
  }

  // Nonce check.
  const combined = new Uint8Array(authDataBytes.byteLength + clientDataHash.byteLength);
  combined.set(authDataBytes, 0);
  combined.set(clientDataHash, authDataBytes.byteLength);
  const expectedNonceB64 = createHash('sha256').update(combined).digest('base64');
  if (payload.nonce !== expectedNonceB64) {
    throwAttestationInvalid(
      `android-safetynet: payload.nonce does not equal base64(SHA-256(authData || clientDataHash))`,
    );
  }

  // Leaf CN check — WebAuthn L3 §8.5 step 3.
  if (!/CN=attest\.android\.com(?:$|\D)/i.test(leaf.subject)) {
    throwAttestationInvalid(
      `android-safetynet: leaf subject CN must be "${LEAF_CN}" (got "${leaf.subject.replace(/\n/g, ' ')}")`,
    );
  }

  // Integrity flags.
  if (payload.basicIntegrity !== true) {
    throwAttestationInvalid('android-safetynet: payload.basicIntegrity is not true');
  }
  if (enforceCtsCheck && payload.ctsProfileMatch !== true) {
    throwAttestationInvalid(
      'android-safetynet: payload.ctsProfileMatch is not true (disable with enforceCtsCheck: false)',
    );
  }

  // Timestamp — accept ±window either side of `now`.
  if (typeof payload.timestampMs !== 'number' || !Number.isFinite(payload.timestampMs)) {
    throwAttestationInvalid('android-safetynet: payload.timestampMs missing or not a finite number');
  }
  if (Math.abs(now - payload.timestampMs) > timestampWindowMs) {
    throwAttestationInvalid(
      `android-safetynet: payload.timestampMs (${payload.timestampMs}) is outside the ±${timestampWindowMs}ms window from now (${now})`,
    );
  }

  // Trust anchor chain verify.
  let trustPath = 'no-anchor';
  if (trustAnchors && trustAnchors.length > 0) {
    try {
      verifyChain({ x5c: chain, trustAnchors: toCertificates(trustAnchors) });
      trustPath = 'trust-anchor';
    } catch (err) {
      throwAttestationTrustAnchorMissing(`android-safetynet: ${err.message}`);
    }
  }

  return {
    format: 'android-safetynet',
    trustPath,
    certChain: chain,
    ctsProfileMatch: payload.ctsProfileMatch === true,
    basicIntegrity: true,
    timestampMs: payload.timestampMs,
  };
}
