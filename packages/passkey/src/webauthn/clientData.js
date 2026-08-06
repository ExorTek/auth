/**
 * Parse and sanity-check `clientDataJSON` — the UTF-8 JSON blob the
 * browser hands us alongside every WebAuthn response.
 *
 * Shape (WebAuthn L3 §5.8.1, "CollectedClientData"):
 *
 *   {
 *     type:           "webauthn.create" | "webauthn.get",
 *     challenge:      <base64url of the server-issued challenge>,
 *     origin:         <the RP's origin, e.g. "https://example.com">,
 *     crossOrigin?:   boolean (default false),
 *     tokenBinding?:  deprecated; ignored
 *   }
 *
 * Deliberate design: this module ONLY parses. Challenge / origin /
 * RP-ID equality checks live next to the flow-specific policy code
 * (`registration.finish`, `authentication.finish`), where the
 * expected values are known. That keeps the parser reusable for
 * both flows without turning it into a soup of optional params.
 */

import { base64url } from '@exortek/crypto/encode';
import { PasskeyError, ErrorCode } from '../errors.js';

/**
 * @typedef {'webauthn.create' | 'webauthn.get'} ClientDataType
 *
 * @typedef {object} ParsedClientData
 * @property {ClientDataType} type
 * @property {Uint8Array} challenge      base64url-decoded raw challenge
 * @property {string} challengeBase64Url original base64url string
 * @property {string} origin
 * @property {boolean} crossOrigin
 * @property {Uint8Array} raw             the input bytes, unchanged
 */

const VALID_TYPES = new Set(['webauthn.create', 'webauthn.get']);

/**
 * @param {Uint8Array} bytes  clientDataJSON as received
 * @returns {ParsedClientData}
 */
export function parseClientData(bytes) {
  if (!(bytes instanceof Uint8Array)) {
    throw new PasskeyError(ErrorCode.CLIENT_DATA_INVALID, 'clientData: expected Uint8Array');
  }
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch (err) {
    throw new PasskeyError(ErrorCode.CLIENT_DATA_INVALID, `clientData: not valid UTF-8 (${err.message})`);
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new PasskeyError(ErrorCode.CLIENT_DATA_INVALID, `clientData: not valid JSON (${err.message})`);
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new PasskeyError(ErrorCode.CLIENT_DATA_INVALID, 'clientData: root must be a JSON object');
  }

  const { type, challenge, origin, crossOrigin } = parsed;

  if (!VALID_TYPES.has(type)) {
    throw new PasskeyError(
      ErrorCode.CLIENT_DATA_INVALID,
      `clientData: type "${type}" is not "webauthn.create" or "webauthn.get"`,
    );
  }
  if (typeof challenge !== 'string' || challenge.length === 0) {
    throw new PasskeyError(ErrorCode.CLIENT_DATA_INVALID, 'clientData: challenge missing or not a string');
  }
  if (typeof origin !== 'string' || origin.length === 0) {
    throw new PasskeyError(ErrorCode.CLIENT_DATA_INVALID, 'clientData: origin missing or not a string');
  }
  if (crossOrigin !== undefined && typeof crossOrigin !== 'boolean') {
    throw new PasskeyError(ErrorCode.CLIENT_DATA_INVALID, 'clientData: crossOrigin must be a boolean when present');
  }

  let challengeBytes;
  try {
    challengeBytes = new Uint8Array(base64url.decode(challenge));
  } catch (err) {
    throw new PasskeyError(
      ErrorCode.CLIENT_DATA_INVALID,
      `clientData: challenge is not valid base64url (${err.message})`,
    );
  }
  if (challengeBytes.byteLength === 0) {
    throw new PasskeyError(ErrorCode.CLIENT_DATA_INVALID, 'clientData: challenge decoded to zero bytes');
  }

  return {
    type,
    challenge: challengeBytes,
    challengeBase64Url: challenge,
    origin,
    crossOrigin: crossOrigin === true,
    raw: bytes,
  };
}
