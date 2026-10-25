/**
 * Minimal OP-metadata fetch for the fields `@exortek/oauth2`'s (private)
 * discovery does not surface to the RP — chiefly `end_session_endpoint` and
 * `check_session_iframe`. The login flow's discovery still runs inside oauth2;
 * this is only reached by `endSessionUrl` when the caller has not supplied an
 * explicit endpoint. Results are cached per issuer for the process lifetime,
 * up to {@link MAX_CACHED_ISSUERS} issuers (oldest dropped first).
 */
import { fetchCapped } from '@exortek/shared/fetch-capped';
import { isObject } from '@exortek/shared/predicates';

import { ErrorCode, OidcError } from './errors.js';

const WELL_KNOWN = '.well-known/openid-configuration';
const DEFAULT_TIMEOUT_MS = 8_000;
const MAX_RESPONSE_BYTES = 1_048_576; // 1 MB
const MAX_CACHED_ISSUERS = 100;

/** @type {Map<string, Record<string, unknown>>} */
const cache = new Map();

/**
 * Resolve (and cache) the OP metadata document for `issuer`.
 *
 * @param {string} issuer
 * @param {{ timeout?: number, fetchImpl?: typeof fetch }} [options]
 * @returns {Promise<Record<string, unknown>>}
 */
export async function resolveIssuerMetadata(issuer, options = {}) {
  const cached = cache.get(issuer);
  if (cached) {
    return cached;
  }

  const url = new URL(WELL_KNOWN, issuer.endsWith('/') ? issuer : `${issuer}/`).toString();
  const { response: res, text } = await fetchCapped(
    url,
    {},
    {
      timeoutMs: options.timeout ?? DEFAULT_TIMEOUT_MS,
      maxBytes: MAX_RESPONSE_BYTES,
      fetchImpl: options.fetchImpl,
      fail: (_reason, message, cause) =>
        new OidcError(ErrorCode.DISCOVERY_FAILED, `OP metadata fetch for ${issuer} failed: ${message}`, { cause }),
    },
  );
  if (!res.ok) {
    throw new OidcError(ErrorCode.DISCOVERY_FAILED, `OP metadata fetch for ${issuer} returned HTTP ${res.status}`);
  }

  /** @type {unknown} */
  let doc;
  try {
    doc = JSON.parse(text);
  } catch (err) {
    throw new OidcError(ErrorCode.DISCOVERY_FAILED, `OP metadata for ${issuer} is not valid JSON`, { cause: err });
  }

  if (!isObject(doc) || doc.issuer !== issuer) {
    throw new OidcError(ErrorCode.DISCOVERY_FAILED, `OP metadata issuer mismatch for ${issuer}`);
  }
  if (cache.size >= MAX_CACHED_ISSUERS) {
    cache.delete(cache.keys().next().value);
  }
  cache.set(issuer, doc);
  return doc;
}

/** Clear the metadata cache — test-only. */
export function _clearIssuerMetadataCache() {
  cache.clear();
}
