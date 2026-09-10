/**
 * Minimal OP-metadata fetch for the fields `@exortek/oauth2`'s (private)
 * discovery does not surface to the RP — chiefly `end_session_endpoint` and
 * `check_session_iframe`. The login flow's discovery still runs inside oauth2;
 * this is only reached by `endSessionUrl` when the caller has not supplied an
 * explicit endpoint. Results are cached per issuer for the process lifetime.
 */
import { isObject } from '@exortek/shared/predicates';

import { ErrorCode, OidcError } from './errors.js';

const WELL_KNOWN = '.well-known/openid-configuration';
const DEFAULT_TIMEOUT_MS = 8_000;

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
  const doFetch = options.fetchImpl ?? fetch;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeout ?? DEFAULT_TIMEOUT_MS);

  /** @type {Record<string, unknown>} */
  let doc;
  try {
    // A discovery endpoint never legitimately redirects — refuse it (SSRF).
    const res = await doFetch(url, { redirect: 'manual', signal: controller.signal });
    if (!res.ok) {
      throw new OidcError(ErrorCode.DISCOVERY_FAILED, `OP metadata fetch for ${issuer} returned HTTP ${res.status}`);
    }
    doc = await res.json();
  } catch (err) {
    if (err instanceof OidcError) {
      throw err;
    }
    throw new OidcError(ErrorCode.DISCOVERY_FAILED, `OP metadata fetch for ${issuer} failed`, { cause: err });
  } finally {
    clearTimeout(timer);
  }

  if (!isObject(doc) || doc.issuer !== issuer) {
    throw new OidcError(ErrorCode.DISCOVERY_FAILED, `OP metadata issuer mismatch for ${issuer}`);
  }
  cache.set(issuer, doc);
  return doc;
}

/** Clear the metadata cache — test-only. */
export function _clearIssuerMetadataCache() {
  cache.clear();
}
