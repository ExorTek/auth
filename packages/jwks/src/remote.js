/**
 * Remote JWKS — fetch, cache, and resolve keys from a remote
 * `/.well-known/jwks.json` endpoint with automatic kid-miss refetch.
 *
 * Returns a resolver function compatible with `jwt.verify(token, resolver)`.
 */

import { importJWK } from '@exortek/jwk/import';
import { validate } from '@exortek/jwk/validate';
import { parseDuration } from '@exortek/shared/duration';
import { isString, isFunction, isObject } from '@exortek/shared/predicates';
import { JwksError, ErrorCode } from './errors.js';
import { assertNonEmptyString, invalidArgument } from './internal/guards.js';

/**
 * @typedef {object} RemoteJWKSOptions
 * @property {boolean}        [cache=true]           enable response caching
 * @property {string|number}  [cacheTtl='10m']       cache lifetime (ms or duration string)
 * @property {number}         [maxCacheKeys=100]     max cached KeyObjects kept in memory (LRU eviction)
 * @property {number}         [cooldownMs=10000]     min ms between refetches on kid-miss
 * @property {number}         [timeout=5000]         fetch timeout in ms
 * @property {boolean}        [allowInsecure=false]   allow http:// URIs (default https only)
 * @property {boolean}        [staleWhileError=false] serve stale cached keys when a refetch fails
 * @property {AbortSignal}    [signal]               caller-provided AbortSignal forwarded to fetch
 * @property {Record<string, string>} [headers]      extra headers sent on the fetch request
 * @property {(header: { kid: string, alg?: string }, error: Error) => void} [onInvalidKey] called when a key cannot be resolved (kid not found or alg mismatch)
 */

/**
 * Create a remote JWKS resolver that fetches and caches keys from `uri`.
 *
 * The returned function has the `async (header) => KeyObject` signature
 * expected by `@exortek/jws` and `@exortek/jwt` verify surfaces.
 *
 * @param {string} uri  The JWKS endpoint URL.
 * @param {RemoteJWKSOptions} [options]
 * @returns {((header: { kid: string, alg?: string }) => Promise<import('node:crypto').KeyObject>) & { reload: () => Promise<void>, cachedKids: () => string[] }}
 */
export function createRemoteJWKS(uri, options = {}) {
  assertNonEmptyString(uri, 'createRemoteJWKS.uri');

  const parsed = new URL(uri);
  const {
    cache: cacheEnabled = true,
    cacheTtl: cacheTtlInput = '10m',
    maxCacheKeys = 100,
    cooldownMs = 10_000,
    timeout = 5_000,
    allowInsecure = false,
    staleWhileError = false,
    signal: externalSignal,
    headers: extraHeaders,
    onInvalidKey,
  } = options;

  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw invalidArgument('createRemoteJWKS.uri must use http or https');
  }
  if (parsed.protocol === 'http:' && !allowInsecure) {
    throw invalidArgument('createRemoteJWKS.uri must use https (pass allowInsecure: true to allow http)');
  }

  if (onInvalidKey !== undefined && !isFunction(onInvalidKey)) {
    throw invalidArgument('createRemoteJWKS.options.onInvalidKey must be a function');
  }

  const cacheTtl = parseDuration(cacheTtlInput);

  /** @type {Map<string, Record<string, unknown>> | null} */
  let jwksCache = null;
  /** @type {number} */
  let cachedAt = 0;
  /** @type {number} */
  let lastFetchAt = 0;
  /** @type {Promise<void> | null} */
  let inflightFetch = null;

  /**
   * Fetch the remote JWKS document. Concurrent callers coalesce onto a
   * single in-flight request. On success the `jwksCache` and
   * `keyObjectCache` are replaced; on failure the old cache survives
   * but `lastFetchAt` is still updated so cooldown applies.
   *
   * @returns {Promise<void>}
   */
  async function fetchJWKS() {
    if (inflightFetch) {
      await inflightFetch;
      return;
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    if (externalSignal) {
      externalSignal.addEventListener('abort', () => controller.abort(), { once: true });
    }

    async function doFetch() {
      /** @type {Response} */
      let res;
      try {
        res = await fetch(uri, {
          signal: controller.signal,
          headers: { accept: 'application/json', ...extraHeaders },
        });
      } catch (err) {
        if (err instanceof Error && err.name === 'AbortError') {
          throw new JwksError(ErrorCode.FETCH_FAILED, `JWKS fetch timed out after ${timeout}ms: ${uri}`);
        }
        throw err;
      } finally {
        clearTimeout(timer);
      }

      if (!res.ok) {
        throw new JwksError(ErrorCode.FETCH_FAILED, `JWKS fetch failed: ${uri} responded with ${res.status}`);
      }

      const body = await res.json();
      if (!isObject(body) || !Array.isArray(body.keys)) {
        throw new JwksError(
          ErrorCode.FETCH_FAILED,
          `JWKS response from ${uri} is not a valid JWK Set (missing "keys" array)`,
        );
      }

      /** @type {Map<string, Record<string, unknown>>} */
      const keyMap = new Map();
      for (const jwk of body.keys) {
        if (!isObject(jwk) || !isString(jwk.kid)) {
          continue;
        }
        try {
          validate(/** @type {Record<string, unknown>} */ (jwk), { requirePublic: true });
          keyMap.set(/** @type {string} */ (jwk.kid), /** @type {Record<string, unknown>} */ (jwk));
        } catch {
          // skip keys we cannot validate — providers may include
          // algorithms or key types we do not support
        }
      }

      jwksCache = keyMap;
      keyObjectCache.clear();
      cachedAt = Date.now();
    }

    inflightFetch = doFetch().finally(() => {
      lastFetchAt = Date.now();
      inflightFetch = null;
    });

    await inflightFetch;
  }

  /** @returns {boolean} */
  function isCacheStale() {
    return !jwksCache || (cacheEnabled && Date.now() - cachedAt > cacheTtl);
  }

  /** @returns {boolean} */
  function canRefetch() {
    return Date.now() - lastFetchAt >= cooldownMs;
  }

  /** @type {Map<string, import('node:crypto').KeyObject>} */
  const keyObjectCache = new Map();

  /**
   * Resolve a cached `KeyObject` for `kid`, importing the JWK on first
   * access (LRU eviction when `maxCacheKeys` is reached). Returns
   * `null` when the kid is not in the JWKS.
   *
   * @param {string} kid
   * @returns {Promise<import('node:crypto').KeyObject | null>}
   */
  async function getKeyObject(kid) {
    if (keyObjectCache.has(kid)) {
      const cached = /** @type {import('node:crypto').KeyObject} */ (keyObjectCache.get(kid));
      keyObjectCache.delete(kid);
      keyObjectCache.set(kid, cached);
      return cached;
    }

    const jwk = jwksCache?.get(kid);
    if (!jwk) {
      return null;
    }

    const keyObject = await importJWK(jwk);

    if (keyObjectCache.size >= maxCacheKeys) {
      const first = keyObjectCache.keys().next().value;
      keyObjectCache.delete(/** @type {string} */ (first));
    }
    keyObjectCache.set(kid, keyObject);

    return keyObject;
  }

  /**
   * Resolve a key by JWT/JWS header. Compatible with
   * `jwt.verify(token, resolver)` and `jws.verify(token, { key: resolver })`.
   *
   * On a cache miss for an unknown `kid` the endpoint is re-fetched once
   * (rate-limited by `cooldownMs`) so provider-side key rotations are
   * picked up without waiting for the full `cacheTtl` to expire.
   *
   * @param {{ kid: string, alg?: string }} header
   * @returns {Promise<import('node:crypto').KeyObject>}
   */
  async function resolver(header) {
    const kid = header?.kid;
    if (!isString(kid) || kid === '') {
      throw new JwksError(ErrorCode.KID_NOT_FOUND, 'token has no "kid" header — cannot resolve key from remote JWKS');
    }

    if (isCacheStale()) {
      if (canRefetch()) {
        try {
          await fetchJWKS();
        } catch (err) {
          if (!staleWhileError || !jwksCache) {
            throw err;
          }
        }
      } else if (!jwksCache) {
        throw new JwksError(ErrorCode.FETCH_FAILED, `JWKS at ${uri} has not been fetched yet and cooldown is active`);
      }
    }

    let key = await getKeyObject(kid);
    if (key) {
      if (isString(header.alg) && jwksCache?.get(kid)?.alg && jwksCache.get(kid).alg !== header.alg) {
        const err = new JwksError(
          ErrorCode.KID_NOT_FOUND,
          `kid=${JSON.stringify(kid)} found but alg mismatch: key has ${jwksCache.get(kid).alg}, token has ${header.alg}`,
        );
        if (onInvalidKey) {
          onInvalidKey(header, err);
        }
        throw err;
      }
      return key;
    }

    // kid-miss refetch — provider may have rotated keys
    if (canRefetch()) {
      try {
        await fetchJWKS();
      } catch (err) {
        if (!staleWhileError || !jwksCache) {
          throw err;
        }
      }
      key = await getKeyObject(kid);
      if (key) {
        return key;
      }
    }

    const notFoundErr = new JwksError(
      ErrorCode.KID_NOT_FOUND,
      `no key with kid=${JSON.stringify(kid)} in the JWKS at ${uri}`,
    );
    if (onInvalidKey) {
      onInvalidKey(header, notFoundErr);
    }
    throw notFoundErr;
  }

  /** Force-clear the cache and re-fetch the remote JWKS endpoint. */
  resolver.reload = async function reload() {
    keyObjectCache.clear();
    jwksCache = null;
    await fetchJWKS();
  };

  /** @returns {string[]} The `kid` values currently held in cache. */
  resolver.cachedKids = function cachedKids() {
    return jwksCache ? [...jwksCache.keys()] : [];
  };

  return resolver;
}
