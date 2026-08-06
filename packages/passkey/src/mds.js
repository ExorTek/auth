/**
 * FIDO Metadata Service v3 (MDS3) blob verifier + AAGUID index
 * builder.
 *
 * Public API for the `@exortek/passkey/mds` subpath. The MDS3 blob
 * is a compact JWS (`<header>.<payload>.<sig>`) whose payload is a
 * JSON MetadataBLOBPayload with per-authenticator statements. The
 * signature chains up to the FIDO Alliance MDS3 root CA.
 *
 * We DO NOT bundle the FIDO MDS3 root CA — it changes on rotation,
 * and pinning the wrong one would silently reject legitimate blobs.
 * The caller supplies `rootAnchors` (fetched from the FIDO
 * Alliance website or vendored into their own trust store).
 *
 * Live URL: https://mds3.fidoalliance.org/  (recommended cadence:
 * daily fetch, cache the blob until nextUpdate).
 *
 * Reference: FIDO Metadata Service v3.0
 * (https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html).
 */

import { createVerify, X509Certificate } from 'node:crypto';
import { base64url } from '@exortek/crypto/encode';
import { verifyChain, toCertificates } from './x509/chain.js';
import { PasskeyError, ErrorCode } from './errors.js';
import { isString, isArray, isObject } from '@exortek/shared/predicates';

function decodeBase64UrlBytes(str, label) {
  try {
    return new Uint8Array(base64url.decode(str));
  } catch (err) {
    throw new PasskeyError(ErrorCode.MDS_BLOB_INVALID, `mds: ${label} is not valid base64url (${err.message})`);
  }
}

function decodeJsonSegment(str, label) {
  const bytes = decodeBase64UrlBytes(str, label);
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch (err) {
    throw new PasskeyError(ErrorCode.MDS_BLOB_INVALID, `mds: ${label} is not valid UTF-8 (${err.message})`);
  }
  try {
    return JSON.parse(text);
  } catch (err) {
    throw new PasskeyError(ErrorCode.MDS_BLOB_INVALID, `mds: ${label} is not valid JSON (${err.message})`);
  }
}

/**
 * Verify an MDS3 blob and return the parsed payload plus a chain
 * of X509Certificates. Throws on any failure.
 *
 * @param {string} jwsCompact
 * @param {object} options
 * @param {Array<import('node:crypto').X509Certificate | Uint8Array | string>} options.rootAnchors
 * @param {number} [options.now]  epoch ms; defaults to Date.now()
 * @returns {{
 *   header: Record<string, unknown>,
 *   payload: {
 *     legalHeader?: string,
 *     no: number,
 *     nextUpdate: string,
 *     entries: Array<Record<string, unknown>>,
 *   },
 *   certChain: import('node:crypto').X509Certificate[],
 * }}
 */
export function verifyMdsBlob(jwsCompact, options) {
  if (!isString(jwsCompact) || jwsCompact.length === 0) {
    throw new PasskeyError(ErrorCode.MDS_BLOB_INVALID, 'mds: jwsCompact must be a non-empty string');
  }
  if (!options || !isArray(options.rootAnchors) || options.rootAnchors.length === 0) {
    throw new PasskeyError(ErrorCode.MDS_BLOB_INVALID, 'mds: rootAnchors (non-empty array) is required');
  }
  const parts = jwsCompact.split('.');
  if (parts.length !== 3) {
    throw new PasskeyError(ErrorCode.MDS_BLOB_INVALID, 'mds: JWS must have three segments');
  }
  const [headerB64, payloadB64, sigB64] = parts;
  const header = decodeJsonSegment(headerB64, 'header');
  const payload = decodeJsonSegment(payloadB64, 'payload');
  const sig = decodeBase64UrlBytes(sigB64, 'signature');

  if (header.alg !== 'RS256' && header.alg !== 'ES256') {
    throw new PasskeyError(ErrorCode.MDS_BLOB_INVALID, `mds: header.alg must be RS256 or ES256 (got "${header.alg}")`);
  }
  if (!isArray(header.x5c) || header.x5c.length === 0) {
    throw new PasskeyError(ErrorCode.MDS_BLOB_INVALID, 'mds: header.x5c must be a non-empty array');
  }
  const chain = header.x5c.map((b64, i) => {
    try {
      return new X509Certificate(Buffer.from(b64, 'base64'));
    } catch (err) {
      throw new PasskeyError(ErrorCode.MDS_BLOB_INVALID, `mds: x5c[${i}] not a valid certificate (${err.message})`);
      return null;
    }
  });
  const leaf = chain[0];

  // Signature verifies over ASCII bytes of `<header>.<payload>`.
  const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const digest = header.alg === 'RS256' ? 'RSA-SHA256' : 'SHA256';
  const v = createVerify(digest);
  v.update(signingInput);
  const opts = header.alg === 'ES256' ? { key: leaf.publicKey, dsaEncoding: 'der' } : leaf.publicKey;
  if (!v.verify(opts, sig)) {
    throw new PasskeyError(ErrorCode.MDS_BLOB_INVALID, 'mds: JWS signature does not verify against leaf certificate');
  }

  // Chain terminates at an RP-supplied root.
  try {
    verifyChain({
      x5c: chain,
      trustAnchors: toCertificates(options.rootAnchors),
      now: options.now ? new Date(options.now) : undefined,
    });
  } catch (err) {
    throw new PasskeyError(ErrorCode.ATTESTATION_TRUST_ANCHOR_MISSING, `mds: ${err.message}`);
  }

  if (!isObject(payload) || !isArray(payload.entries)) {
    throw new PasskeyError(ErrorCode.MDS_BLOB_INVALID, 'mds: payload.entries must be an array');
  }
  if (typeof payload.no !== 'number') {
    throw new PasskeyError(ErrorCode.MDS_BLOB_INVALID, 'mds: payload.no must be a number');
  }
  // nextUpdate is a plain YYYY-MM-DD string. We do not enforce
  // freshness ourselves — callers who care compare Date.now() to it.

  return { header, payload, certChain: chain };
}

/**
 * Build a `{ aaguid: entry }` index from an MDS3 payload.
 *
 * @param {{ entries: Array<Record<string, unknown>> }} mdsPayload
 * @returns {Record<string, { name: string, statement: object }>}
 */
export function buildAaguidIndex(mdsPayload) {
  if (!mdsPayload || !isArray(mdsPayload.entries)) {
    throw new PasskeyError(ErrorCode.MDS_BLOB_INVALID, 'mds: buildAaguidIndex requires a payload with .entries');
  }
  const out = {};
  for (const entry of mdsPayload.entries) {
    const statement = entry?.metadataStatement;
    if (!statement) {
      continue;
    }
    const aaguid = statement.aaguid || entry.aaguid;
    if (!isString(aaguid) || aaguid.length === 0) {
      continue;
    }
    const name = statement.description ?? aaguid;
    out[aaguid] = { name, statement };
  }
  return out;
}
