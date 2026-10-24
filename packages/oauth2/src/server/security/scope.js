/**
 * Scope ceiling — the single rule every grant applies to a requested scope.
 * A client may only ever be granted scopes that BOTH the server advertises
 * (`config.scopes`) and its own registration lists (`client.scope`). Taking
 * either one alone is an escalation lever: a dynamically-registered client
 * picks its own `scope`, so trusting it instead of the server list would let
 * a registrant grant itself anything.
 */
import { isArray, isNonEmptyString } from '@exortek/shared/predicates';

import { ProtocolError, ServerError } from '../errors.js';

/**
 * The scopes `client` may be granted, or `undefined` when neither the server
 * nor the client declares a list (no ceiling configured).
 *
 * @param {import('../clients.js').Client} client
 * @param {Record<string, any>} config
 * @returns {string[] | undefined}
 */
export function scopeCeiling(client, config) {
  const own = isArray(client.scope) ? client.scope : undefined;
  const server = isArray(config.scopes) ? config.scopes : undefined;
  if (own && server) {
    return own.filter(s => server.includes(s));
  }
  return own ?? server;
}

/**
 * Split a space-delimited `scope` parameter (RFC 6749 §3.3).
 *
 * @param {unknown} raw
 * @returns {string[]}
 */
export function parseScope(raw) {
  return isNonEmptyString(raw) ? raw.split(/\s+/).filter(Boolean) : [];
}

/**
 * Throw `invalid_scope` for the first requested scope outside the ceiling.
 *
 * @param {string[]} requested
 * @param {string[] | undefined} ceiling
 * @param {{ redirectable?: boolean, state?: string }} [errorOptions]
 */
export function assertWithinCeiling(requested, ceiling, errorOptions) {
  if (!isArray(ceiling)) {
    return;
  }
  for (const s of requested) {
    if (!ceiling.includes(s)) {
      throw new ServerError(
        ProtocolError.INVALID_SCOPE,
        `scope ${JSON.stringify(s)} is not permitted for this client`,
        errorOptions,
      );
    }
  }
}
