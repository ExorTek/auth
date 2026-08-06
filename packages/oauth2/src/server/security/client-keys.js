/**
 * Resolve a client's public verification keys for the signature-based
 * flows (`private_key_jwt` client auth, JAR request objects). A client
 * registers either a `jwksUri` (fetched + cached via `@exortek/jwks`) or
 * an inline `jwks` JWK Set. Both resolve to something `@exortek/jwt`'s
 * `verify` accepts as `keyish`: the remote set is already a resolver; the
 * inline set becomes a `kid`-aware resolver so a signed token's `kid`
 * selects the right key (importing to bare KeyObjects would drop the
 * `kid` and break selection).
 */
import { createRemoteJWKS } from '@exortek/jwks';
import { importJWK } from '@exortek/jwk';
import { isArray, isNonEmptyString, isObject } from '@exortek/shared/predicates';

import { ProtocolError, ServerError } from '../errors.js';

/**
 * @param {import('../clients.js').Client} client
 * @param {{ allowJwksHost?: (hostname: string, url: URL) => boolean }} [options]
 *   `allowJwksHost` gates the destination of a `jwksUri` fetch. A client's
 *   `jwks_uri` is client-supplied — under open or token-gated dynamic
 *   registration it is chosen by whoever registered — so a deployment can
 *   constrain which hosts the server will reach out to.
 * @returns {Promise<Function>} a `keyish` resolver for `jwt.verify`
 */
export async function resolveClientKeys(client, options = {}) {
  if (isNonEmptyString(client.jwksUri)) {
    try {
      return createRemoteJWKS(client.jwksUri, {
        ...(options.allowJwksHost ? { allowHost: options.allowJwksHost } : {}),
      });
    } catch (err) {
      throw new ServerError(
        ProtocolError.INVALID_CLIENT,
        `client jwks_uri was refused: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }
  if (isObject(client.jwks) && isArray(client.jwks.keys) && client.jwks.keys.length > 0) {
    const entries = await Promise.all(
      client.jwks.keys.map(async jwk => [isNonEmptyString(jwk.kid) ? jwk.kid : undefined, await importJWK(jwk)]),
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
      throw new ServerError(
        ProtocolError.INVALID_CLIENT,
        'the signed token has no kid but the client has multiple keys',
      );
    };
  }
  throw new ServerError(ProtocolError.INVALID_CLIENT, `client ${JSON.stringify(client.clientId)} has no JWKS`);
}
