/**
 * Parse `authenticatorData` — the fixed-prefix binary blob every
 * WebAuthn credential response includes. Layout (WebAuthn L3 §6.1):
 *
 *   rpIdHash                    32 bytes  SHA-256(RP ID)
 *   flags                        1 byte   see ./flags.js
 *   signCount                    4 bytes  big-endian uint32
 *   [attestedCredentialData]              iff AT flag set (§6.5.2)
 *     aaguid                    16 bytes
 *     credentialIdLength         2 bytes  big-endian uint16 (≤ 1023)
 *     credentialId              <length> bytes
 *     credentialPublicKey                 CBOR-encoded COSE Key
 *   [extensions]                          iff ED flag set — a CBOR map
 *
 * Registration responses include attestedCredentialData; assertion
 * responses do not. Extensions are optional in both.
 */

import { decodeWithLength } from '../cbor/decode.js';
import { decodeFlags } from './flags.js';

const MIN_AUTH_DATA = 37; // rpIdHash 32 + flags 1 + counter 4
const AAGUID_LEN = 16;
const MAX_CRED_ID_LEN = 1023; // CTAP2 §11.2.2 limit — anything larger is malformed

/**
 * Format a 16-byte AAGUID as the canonical `xxxxxxxx-xxxx-xxxx-
 * xxxx-xxxxxxxxxxxx` string used by MDS and browsers.
 *
 * @param {Uint8Array} aaguid
 * @returns {string}
 */
export function formatAaguid(aaguid) {
  if (!(aaguid instanceof Uint8Array) || aaguid.byteLength !== AAGUID_LEN) {
    throw new Error(`authData: AAGUID must be a 16-byte Uint8Array (got ${aaguid?.byteLength})`);
  }
  const hex = Array.from(aaguid, b => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

/**
 * @typedef {import('./flags.js').AuthFlags} AuthFlags
 *
 * @typedef {object} AttestedCredentialData
 * @property {Uint8Array} aaguid           16 bytes.
 * @property {string} aaguidString         Canonical hyphenated form.
 * @property {Uint8Array} credentialId
 * @property {Map<number, unknown>} credentialPublicKey
 *   Raw COSE Key Map — feed to `importCoseKey` for a `KeyObject`.
 * @property {Uint8Array} credentialPublicKeyBytes
 *   The exact CBOR bytes that encoded the public key. Kept because
 *   some attestation checks re-hash this blob and byte-equality
 *   with the original is required.
 *
 * @typedef {object} ParsedAuthData
 * @property {Uint8Array} rpIdHash
 * @property {AuthFlags} flags
 * @property {number} signCount
 * @property {AttestedCredentialData | null} attestedCredentialData
 * @property {Map<unknown, unknown> | null} extensions  Raw decoded map, or null.
 * @property {Uint8Array} raw                            The input bytes, unchanged.
 */

/**
 * Parse an authenticator-data blob. Throws with an explicit reason
 * on any length / structure violation.
 *
 * @param {Uint8Array} bytes
 * @returns {ParsedAuthData}
 */
export function parseAuthData(bytes) {
  if (!(bytes instanceof Uint8Array)) {
    throw new Error('authData: expected Uint8Array');
  }
  if (bytes.byteLength < MIN_AUTH_DATA) {
    throw new Error(`authData: too short — need at least ${MIN_AUTH_DATA} bytes, got ${bytes.byteLength}`);
  }

  const rpIdHash = bytes.subarray(0, 32);
  const flags = decodeFlags(bytes[32]);
  // Big-endian uint32 sign counter. DataView reads with an explicit
  // byte offset — pass the underlying buffer + offset so a subarray
  // input is handled correctly.
  const signCount = new DataView(bytes.buffer, bytes.byteOffset + 33, 4).getUint32(0, false);

  let pos = MIN_AUTH_DATA;
  let attestedCredentialData = null;

  if (flags.at) {
    if (bytes.byteLength < pos + AAGUID_LEN + 2) {
      throw new Error('authData: AT flag set but attested credential data is truncated');
    }
    const aaguid = bytes.subarray(pos, pos + AAGUID_LEN);
    pos += AAGUID_LEN;

    const credIdLen = new DataView(bytes.buffer, bytes.byteOffset + pos, 2).getUint16(0, false);
    pos += 2;
    if (credIdLen === 0) {
      throw new Error('authData: attested credential data credentialIdLength is 0');
    }
    if (credIdLen > MAX_CRED_ID_LEN) {
      throw new Error(`authData: credentialIdLength ${credIdLen} exceeds CTAP2 §11.2.2 max of ${MAX_CRED_ID_LEN}`);
    }
    if (bytes.byteLength < pos + credIdLen) {
      throw new Error(`authData: credentialId declares ${credIdLen} bytes but only ${bytes.byteLength - pos} left`);
    }

    const credentialId = bytes.subarray(pos, pos + credIdLen);
    pos += credIdLen;

    // credentialPublicKey is a CBOR item; extensions may follow, so
    // decodeWithLength reports how many bytes the key consumed.
    const { value: pubKeyValue, bytesRead: keyBytes } = decodeWithLength(bytes.subarray(pos));
    if (!(pubKeyValue instanceof Map)) {
      throw new Error('authData: credentialPublicKey is not a CBOR map');
    }
    const credentialPublicKey = pubKeyValue;
    const credentialPublicKeyBytes = bytes.subarray(pos, pos + keyBytes);
    pos += keyBytes;

    attestedCredentialData = {
      aaguid,
      aaguidString: formatAaguid(aaguid),
      credentialId,
      credentialPublicKey,
      credentialPublicKeyBytes,
    };
  }

  let extensions = null;
  if (flags.ed) {
    if (pos >= bytes.byteLength) {
      throw new Error('authData: ED flag set but extensions block missing');
    }
    const { value: extValue, bytesRead: extBytes } = decodeWithLength(bytes.subarray(pos));
    if (!(extValue instanceof Map)) {
      throw new Error('authData: extensions is not a CBOR map');
    }
    extensions = extValue;
    pos += extBytes;
  }

  if (pos !== bytes.byteLength) {
    throw new Error(`authData: ${bytes.byteLength - pos} trailing byte(s) after parse`);
  }

  return {
    rpIdHash,
    flags,
    signCount,
    attestedCredentialData,
    extensions,
    raw: bytes,
  };
}
