/**
 * Rich Authorization Requests — RAR (RFC 9396). The `authorization_details`
 * parameter carries a JSON array of typed authorization objects for
 * fine-grained, per-resource consent beyond a flat `scope` string. This
 * module validates the structure at the authorize (or PAR) step; the
 * granted details are stored with the code and reflected into the access
 * token so the resource server can enforce them (RFC 9396 §7).
 *
 * Validation here is structural — each entry is an object with a string
 * `type`. A deployment restricts which `type`s it accepts via the
 * `authorizationDetailsTypes` config; an unlisted type is refused.
 */
import { isNonEmptyString, isObject } from '@exortek/shared/predicates';

import { ProtocolError, ServerError } from '../errors.js';

/**
 * Parse + validate `authorization_details`. Accepts either a JSON string
 * (front-channel query) or an already-parsed array (PAR / JSON body), and
 * returns the normalized array. Absent input returns `undefined`.
 *
 * @param {unknown} raw
 * @param {{ allowedTypes?: string[], redirectableState?: string }} [options]
 * @returns {unknown[] | undefined}
 */
export function validateAuthorizationDetails(raw, options = {}) {
  if (raw === undefined || raw === null || raw === '') {
    return undefined;
  }

  let details = raw;
  if (isNonEmptyString(raw)) {
    try {
      details = JSON.parse(raw);
    } catch {
      throw invalid('authorization_details is not valid JSON', options.redirectableState);
    }
  }
  if (!Array.isArray(details) || details.length === 0) {
    throw invalid('authorization_details must be a non-empty JSON array', options.redirectableState);
  }

  for (const entry of details) {
    if (!isObject(entry) || !isNonEmptyString(entry.type)) {
      throw invalid(
        'each authorization_details entry must be an object with a string "type"',
        options.redirectableState,
      );
    }
    if (Array.isArray(options.allowedTypes) && !options.allowedTypes.includes(entry.type)) {
      throw invalid(
        `authorization_details type ${JSON.stringify(entry.type)} is not supported`,
        options.redirectableState,
      );
    }
  }
  return details;
}

/**
 * @param {string} message
 * @param {string | undefined} state
 * @returns {ServerError}
 */
function invalid(message, state) {
  return new ServerError(ProtocolError.INVALID_AUTHORIZATION_DETAILS, message, {
    redirectable: state !== undefined,
    state,
  });
}
