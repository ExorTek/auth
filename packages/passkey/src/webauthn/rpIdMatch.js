/**
 * Match `authData.rpIdHash` (32 bytes, SHA-256 of the RP ID) against
 * one or more expected RP IDs.
 *
 * Supports the WebAuthn L3 "related origins" story: a single RP may
 * legitimately have several RP IDs across country-code top-level
 * domains (`example.com`, `example.co.uk`, …). Callers pass an
 * array and we return which one matched — useful for downstream
 * accounting, logging, or per-tenant policy.
 */

import { createHash } from 'node:crypto';
import { bytesEqual } from '../internal/bytes.js';

/**
 * @param {string} rpId
 * @returns {Uint8Array}
 */
function sha256(rpId) {
  return new Uint8Array(createHash('sha256').update(rpId, 'utf8').digest());
}

/**
 * @param {Uint8Array} rpIdHash             32-byte hash from authData
 * @param {string | string[]} expectedRpId  one RP ID or an ordered list
 * @returns {{ matched: string } | null}   the RP ID that matched, or null
 */
export function matchRpId(rpIdHash, expectedRpId) {
  if (!(rpIdHash instanceof Uint8Array) || rpIdHash.byteLength !== 32) {
    throw new Error('rpIdMatch: rpIdHash must be a 32-byte Uint8Array');
  }
  const candidates = Array.isArray(expectedRpId) ? expectedRpId : [expectedRpId];
  if (candidates.length === 0) {
    throw new Error('rpIdMatch: expectedRpId list is empty');
  }
  for (const candidate of candidates) {
    if (typeof candidate !== 'string' || candidate.length === 0) {
      throw new Error('rpIdMatch: expectedRpId entries must be non-empty strings');
    }
    if (bytesEqual(rpIdHash, sha256(candidate))) {
      return { matched: candidate };
    }
  }
  return null;
}
