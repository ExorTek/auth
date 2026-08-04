/**
 * Resource Indicators (RFC 8707). A `resource` parameter names the
 * protected resource a token is for, so the issued access token's `aud`
 * is restricted to that resource — a leaked token can't be replayed at a
 * different API. Each value must be an absolute URI with no fragment
 * (RFC 8707 §2); anything else is `invalid_target`.
 *
 * The audience bound at the authorize step (stored with the code /
 * refresh family) is the ceiling: a token request may narrow to it but
 * never widen beyond it.
 */
import { isNonEmptyString } from '@exortek/shared/predicates';

import { ProtocolError, ServerError } from '../errors.js';

/**
 * Validate a single `resource` value as an absolute, fragment-free URI.
 *
 * @param {string} value
 * @returns {string}
 */
export function validateResource(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new ServerError(ProtocolError.INVALID_TARGET, `resource ${JSON.stringify(value)} is not an absolute URI`);
  }
  if (isNonEmptyString(url.hash)) {
    throw new ServerError(ProtocolError.INVALID_TARGET, 'resource URI must not contain a fragment');
  }
  // Return the value as presented (RFC 8707 §2 compares it literally as
  // the resource server's identifier) — do not re-serialize, which would
  // append a trailing slash and break the match.
  return value;
}

/**
 * Resolve the token `aud` from a token-request `resource` and the
 * resource bound at authorize time. When both are present they must
 * agree; a request for an unbound resource is `invalid_target`.
 *
 * @param {string | undefined} requested   `resource` on the token request
 * @param {string | undefined} bound       `resource` captured with the code / family
 * @param {Record<string, any>} _config
 * @returns {string | undefined}           the audience, or undefined when none applies
 */
export function resolveTokenAudience(requested, bound, _config) {
  if (isNonEmptyString(requested)) {
    const normalized = validateResource(requested);
    if (isNonEmptyString(bound) && normalized !== bound) {
      throw new ServerError(ProtocolError.INVALID_TARGET, 'requested resource was not authorized for this grant');
    }
    return normalized;
  }
  return isNonEmptyString(bound) ? bound : undefined;
}
