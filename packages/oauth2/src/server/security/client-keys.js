/**
 * Resolve a client's public verification keys for the signature-based
 * flows (`private_key_jwt` client auth, JAR request objects). A client
 * registers either a `jwksUri` (fetched + cached via `@exortek/jwks`) or
 * an inline `jwks` JWK Set. Both resolve to something `@exortek/jwt`'s
 * `verify` accepts as `keyish`: the remote set is already a resolver; the
 * inline set becomes a `kid`-aware resolver so a signed token's `kid`
 * selects the right key (importing to bare KeyObjects would drop the
 * `kid` and break selection).
 *
 * Resolvers are cached per server: a remote set by its `jwks_uri` (so the
 * JWKS response cache actually survives between requests instead of every
 * token request and every `/authorize?request=` triggering a fetch) and an
 * inline set by the client descriptor.
 */
import { isIP } from 'node:net';

import { createRemoteJWKS } from '@exortek/jwks';
import { importJWK } from '@exortek/jwk';
import { isArray, isFunction, isNonEmptyString, isObject } from '@exortek/shared/predicates';

import { ProtocolError, ServerError } from '../errors.js';

const MAX_REMOTE_RESOLVERS = 1000;

/**
 * @typedef {(client: import('../clients.js').Client) => Promise<Function>} ClientKeyResolver
 */

/**
 * @param {{ allowJwksHost?: (hostname: string, url: URL) => boolean, registrationEnabled?: boolean }} [options]
 *   `allowJwksHost` gates the destination of a `jwksUri` fetch. A client's
 *   `jwks_uri` is client-supplied — under dynamic registration it is chosen
 *   by whoever registered — so when registration is enabled and no gate is
 *   configured, loopback, private and link-local hosts are refused by
 *   default (an SSRF lever into the server's own network).
 * @returns {ClientKeyResolver}
 */
export function createClientKeyResolver(options = {}) {
  const allowHost = isFunction(options.allowJwksHost)
    ? options.allowJwksHost
    : options.registrationEnabled === true
      ? isPublicHost
      : undefined;

  /** @type {Map<string, Function>} jwks_uri → remote resolver (insertion-ordered LRU) */
  const remote = new Map();
  /** @type {WeakMap<object, Promise<Function>>} client descriptor → inline resolver */
  const inline = new WeakMap();

  return async function resolveClientKeys(client) {
    if (isNonEmptyString(client.jwksUri)) {
      const cached = remote.get(client.jwksUri);
      if (cached) {
        remote.delete(client.jwksUri);
        remote.set(client.jwksUri, cached);
        return cached;
      }
      let resolver;
      try {
        resolver = createRemoteJWKS(client.jwksUri, allowHost ? { allowHost } : {});
      } catch (err) {
        throw new ServerError(
          ProtocolError.INVALID_CLIENT,
          `client jwks_uri was refused: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
      if (remote.size >= MAX_REMOTE_RESOLVERS) {
        remote.delete(remote.keys().next().value);
      }
      remote.set(client.jwksUri, resolver);
      return resolver;
    }
    if (isObject(client.jwks) && isArray(client.jwks.keys) && client.jwks.keys.length > 0) {
      let pending = inline.get(client);
      if (!pending) {
        pending = inlineResolver(client.jwks.keys);
        inline.set(client, pending);
        // A key that fails to import must not poison the cache.
        pending.catch(() => inline.delete(client));
      }
      return pending;
    }
    throw new ServerError(ProtocolError.INVALID_CLIENT, `client ${JSON.stringify(client.clientId)} has no JWKS`);
  };
}

/**
 * @param {object[]} keys
 * @returns {Promise<Function>}
 */
async function inlineResolver(keys) {
  const entries = await Promise.all(
    keys.map(async jwk => [isNonEmptyString(jwk.kid) ? jwk.kid : undefined, await importJWK(jwk)]),
  );
  const byKid = new Map(entries.filter(([kid]) => kid !== undefined));
  const all = entries.map(([, key]) => key);
  return header => {
    const kid = header?.kid;
    if (isNonEmptyString(kid)) {
      const match = byKid.get(kid);
      if (match) {
        return match;
      }
      // A named kid that isn't in the set is a hard miss.
      throw new ServerError(ProtocolError.INVALID_CLIENT, `no client key matches kid ${JSON.stringify(kid)}`);
    }
    if (all.length === 1) {
      return all[0];
    }
    throw new ServerError(ProtocolError.INVALID_CLIENT, 'the signed token has no kid but the client has multiple keys');
  };
}

/**
 * Default `jwks_uri` host gate under dynamic registration: refuse names and
 * IP literals that point back into the server's own or private networks.
 * This is a literal check — a public name that resolves to a private
 * address is only stopped by a deployment-supplied `allowJwksHost` (or an
 * egress proxy).
 *
 * @param {string} hostname
 * @returns {boolean}
 */
export function isPublicHost(hostname) {
  const host = hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) {
    return false;
  }
  const family = isIP(host);
  if (family === 4) {
    const [a, b] = host.split('.').map(Number);
    return !(
      a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      a >= 224
    );
  }
  if (family === 6) {
    const mapped = host.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) {
      return isPublicHost(mapped[1]);
    }
    return !(host === '::' || host === '::1' || /^f[cd]/.test(host) || /^fe[89ab]/.test(host) || /^ff/.test(host));
  }
  return true;
}
