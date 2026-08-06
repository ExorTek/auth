/**
 * JAR + JARM (RFC 9101 + OIDC JARM). JAR — the `request` parameter is a
 * signed JWT (a "request object") carrying the authorization parameters,
 * so they are integrity-protected and the client is authenticated at the
 * authorization endpoint. JARM — the authorization RESPONSE is returned as
 * a signed JWT (`response_mode=jwt`), so `code` / `state` / `iss` can't be
 * tampered with in the front channel.
 *
 * Request objects are verified with the client's registered keys (the
 * same JWKS used for `private_key_jwt`); the embedded `client_id` must
 * match the outer one, and the parameters inside the JWT win over any
 * duplicated query parameters (RFC 9101 §5).
 */
import { sign as jwtSign, verify as jwtVerify, decode as jwtDecode, JwtError } from '@exortek/jwt';
import { isNonEmptyString, isNumber, isObject } from '@exortek/shared/predicates';

import { ProtocolError, ServerError } from '../errors.js';
import { resolveClientKeys } from './client-keys.js';
import { createReplayCache } from './replay-cache.js';

// A JAR request object is short-lived; bound its accepted lifetime so a
// captured one cannot be replayed indefinitely, and remember its `jti`
// (when present) for that window so a single-use request object cannot be
// replayed at all. Module-level / single-process, like the DPoP and
// client-assertion caches; a multi-node deployment fronts it with PAR.
const MAX_REQUEST_OBJECT_LIFETIME_MS = 300_000; // 5 minutes
const seenRequestJti = createReplayCache(MAX_REQUEST_OBJECT_LIFETIME_MS);

const REQUEST_OBJECT_ALGS = new Set([
  'ES256',
  'ES384',
  'ES512',
  'RS256',
  'RS384',
  'RS512',
  'PS256',
  'PS384',
  'PS512',
  'EdDSA',
]);

/**
 * Verify a JAR request object and return the authorization parameters it
 * carries. `outerClientId` is the `client_id` sent as a plain parameter
 * (RFC 9101 requires it alongside `request`).
 *
 * @param {string} requestJwt
 * @param {string | undefined} outerClientId
 * @param {Record<string, any>} config
 * @returns {Promise<Record<string, unknown>>}
 */
export async function verifyRequestObject(requestJwt, outerClientId, config) {
  let unverified;
  try {
    unverified = jwtDecode(requestJwt);
  } catch {
    throw new ServerError(ProtocolError.INVALID_REQUEST, 'request object is not a well-formed JWT');
  }

  const clientId = unverified?.payload?.client_id ?? unverified?.payload?.iss;
  if (!isNonEmptyString(clientId) || (isNonEmptyString(outerClientId) && outerClientId !== clientId)) {
    throw new ServerError(ProtocolError.INVALID_REQUEST, 'request object client_id does not match the request');
  }

  const client = await config.registry.getClient(clientId);
  if (!client) {
    throw new ServerError(ProtocolError.INVALID_CLIENT, `unknown client ${JSON.stringify(clientId)}`);
  }

  const alg = unverified.header?.alg;
  if (!isNonEmptyString(alg) || !REQUEST_OBJECT_ALGS.has(alg)) {
    throw new ServerError(ProtocolError.INVALID_REQUEST, `request object alg ${JSON.stringify(alg)} is not accepted`);
  }

  let payload;
  try {
    const keys = await resolveClientKeys(client, { allowJwksHost: config.security?.allowJwksHost });
    payload = (await jwtVerify(requestJwt, keys, { alg: [alg], audience: config.issuer })).payload;
  } catch (err) {
    if (err instanceof JwtError) {
      throw new ServerError(ProtocolError.INVALID_REQUEST, 'request object signature is invalid');
    }
    throw err;
  }

  // RFC 9101 §6.1: the request object must carry `exp`. Bound its lifetime
  // and (when it names a `jti`) reject a reuse — otherwise a front-channel
  // request object with a far-future / absent exp replays forever.
  if (!isNumber(payload.exp)) {
    throw new ServerError(ProtocolError.INVALID_REQUEST, 'request object must set exp');
  }
  if (payload.exp * 1000 - Date.now() > MAX_REQUEST_OBJECT_LIFETIME_MS) {
    throw new ServerError(ProtocolError.INVALID_REQUEST, 'request object lifetime exceeds the accepted maximum');
  }
  if (isNonEmptyString(payload.jti) && seenRequestJti.seen(payload.jti)) {
    throw new ServerError(ProtocolError.INVALID_REQUEST, 'request object jti has already been used (replay)');
  }

  // Project the JWT claims onto authorization parameters. `iss` / `aud` /
  // `exp` / `nbf` are JWT envelope claims, not authorization params.
  const params = { ...payload };
  delete params.iss;
  delete params.aud;
  delete params.exp;
  delete params.nbf;
  delete params.iat;
  delete params.jti;
  params.client_id = clientId;
  return params;
}

/**
 * Sign an authorization response as a JARM JWT (`response` parameter).
 * The AS returns this instead of bare `code` / `state` query params when
 * the client requests `response_mode=jwt`.
 *
 * @param {Record<string, unknown>} responseParams   e.g. `{ code, state, iss }`
 * @param {string} audience                           the client_id
 * @param {Record<string, any>} config
 * @returns {Promise<string>}
 */
export async function signJarmResponse(responseParams, audience, config) {
  if (!isObject(config.jarm) || config.jarm.signingKey === undefined) {
    throw new ServerError(ProtocolError.INVALID_REQUEST, 'this server is not configured to issue JARM responses');
  }
  return jwtSign({ ...responseParams }, config.jarm.signingKey, {
    alg: config.jarm.alg,
    issuer: config.issuer,
    audience,
    expiresIn: 120,
  });
}
