/**
 * Attestation format dispatcher.
 *
 * WebAuthn `attestationObject` decodes to a CBOR map:
 *   { fmt: "<name>", authData: Uint8Array, attStmt: Map }
 *
 * Each format handler takes `{ attStmt, authDataBytes, clientDataHash,
 * attestedCredentialData, trustAnchors, ... }` and returns a small
 * report `{ format, trustPath, ... }`. Formats we don't recognise
 * throw `UNSUPPORTED_ATTESTATION_FORMAT` with a clear message.
 */

import { throwUnsupportedAttestationFormat } from '../errors.js';
import { verifyNone } from './none.js';
import { verifyPacked } from './packed.js';
import { verifyFidoU2f } from './fidoU2f.js';
import { verifyApple } from './apple.js';
import { verifyAndroidSafetynet } from './androidSafetynet.js';
import { verifyAndroidKey } from './androidKey.js';

/**
 * @param {string} fmt
 */
export function getVerifier(fmt) {
  switch (fmt) {
    case 'none':
      return verifyNone;
    case 'packed':
      return verifyPacked;
    case 'fido-u2f':
      return verifyFidoU2f;
    case 'apple':
      return verifyApple;
    case 'android-safetynet':
      return verifyAndroidSafetynet;
    case 'android-key':
      return verifyAndroidKey;
    default:
      throwUnsupportedAttestationFormat(`attestation format "${fmt}" is not supported yet`);
  }
}
