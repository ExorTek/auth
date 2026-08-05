/**
 * Dynamic Client Registration endpoint (RFC 7591). A client POSTs its
 * metadata as JSON and the server mints a `client_id` (and, for a
 * confidential auth method, a `client_secret`), persists it through the
 * registry, and returns the RFC 7591 §3.2.1 response.
 *
 * Secure by default (Decision #0): registration is **opt-in** and, unless
 * a deployment explicitly opens it (`registration.open: true`), requires an
 * initial access token (RFC 7591 §3) — an open `/register` is an abuse
 * vector (anyone can mint clients). The submitted metadata is validated and
 * frozen through {@link import('../clients.js').defineClient}, so a
 * registration can never produce a malformed or downgraded client.
 */
import { timingSafeEqual } from '@exortek/shared/timing-safe';
import { isArray, isFunction, isNonEmptyString, isObject } from '@exortek/shared/predicates';

import { ProtocolError, ServerError } from '../errors.js';
import { OAuth2Error } from '../../internal/errors.js';
import { randomState } from '../../internal/state.js';
import { normalizeRequest } from '../request.js';
import { json, jsonError } from '../response.js';

const SECRET_BASED = new Set(['client_secret_basic', 'client_secret_post', 'client_secret_jwt']);

/**
 * @param {Record<string, any>} config
 * @returns {(raw: import('../request.js').RawRequest) => Promise<import('../response.js').ServerResponse>}
 */
export function createRegisterHandler(config) {
  const reg = isObject(config.registration) ? config.registration : {};

  return async function registerHandler(raw) {
    try {
      const req = normalizeRequest(raw);
      if (req.method !== 'POST') {
        throw new ServerError(ProtocolError.INVALID_REQUEST, 'the registration endpoint only accepts POST');
      }
      if (!isFunction(config.registry.register)) {
        throw new ServerError(
          ProtocolError.INVALID_REQUEST,
          'this server does not support dynamic client registration',
        );
      }

      await authorizeRegistration(req, reg);

      // RFC 7591 §3.1: the body is a JSON client-metadata object.
      const meta = req.form;
      if (!isObject(meta) || Object.keys(meta).length === 0) {
        throw new ServerError(ProtocolError.INVALID_CLIENT_METADATA, 'client metadata is required');
      }

      const clientConfig = buildClientConfig(meta, reg);
      let client;
      try {
        client = config.registry.register(clientConfig);
      } catch (err) {
        // A validation failure from defineClient is a client-metadata error,
        // not a server fault.
        if (err instanceof OAuth2Error) {
          throw new ServerError(ProtocolError.INVALID_CLIENT_METADATA, err.message);
        }
        throw err;
      }

      return json(201, buildResponse(client, clientConfig));
    } catch (err) {
      if (err instanceof ServerError) {
        return jsonError(err);
      }
      throw err;
    }
  };
}

/**
 * Gate registration behind an initial access token unless explicitly opened.
 *
 * @param {import('../request.js').ServerRequest} req
 * @param {Record<string, any>} reg
 */
async function authorizeRegistration(req, reg) {
  // A custom predicate takes over entirely.
  if (isFunction(reg.authorize)) {
    const ok = await reg.authorize(req);
    if (!ok) {
      throw new ServerError(ProtocolError.INVALID_CLIENT, 'registration is not authorized');
    }
    return;
  }
  if (reg.open === true) {
    return;
  }
  if (!isNonEmptyString(reg.initialAccessToken)) {
    // Neither opened nor gated by a token → refuse rather than run open.
    throw new ServerError(ProtocolError.INVALID_CLIENT, 'dynamic registration requires an initial access token');
  }
  const presented = bearer(req.header('authorization'));
  if (!isNonEmptyString(presented) || !constantEquals(presented, reg.initialAccessToken)) {
    throw new ServerError(ProtocolError.INVALID_CLIENT, 'a valid initial access token is required to register');
  }
}

/**
 * Map RFC 7591 snake_case metadata onto the internal client config, layering
 * the deployment's `registration.defaults` under the request. The server owns
 * the generated `client_id` / `client_secret`.
 *
 * @param {Record<string, any>} meta
 * @param {Record<string, any>} reg
 * @returns {import('../clients.js').ClientConfig}
 */
function buildClientConfig(meta, reg) {
  const defaults = isObject(reg.defaults) ? reg.defaults : {};
  const redirectUris = meta.redirect_uris ?? defaults.redirectUris;
  const authMethod = meta.token_endpoint_auth_method ?? defaults.tokenEndpointAuthMethod ?? 'client_secret_basic';

  // RFC 7591 §2 / §3.2.2: a client using a redirect-based grant must supply
  // at least one redirect URI.
  const grantTypes = toArray(meta.grant_types) ?? defaults.grantTypes ?? ['authorization_code'];
  const usesRedirect = grantTypes.includes('authorization_code');
  if (usesRedirect && (!isArray(redirectUris) || redirectUris.length === 0)) {
    throw new ServerError(ProtocolError.INVALID_REDIRECT_URI, 'redirect_uris is required for this grant');
  }

  /** @type {import('../clients.js').ClientConfig} */
  const cfg = {
    clientId: randomState(),
    redirectUris: isArray(redirectUris) ? redirectUris : [],
    tokenEndpointAuthMethod: authMethod,
    grantTypes,
  };
  if (SECRET_BASED.has(authMethod)) {
    cfg.clientSecret = randomState(48);
  }
  const responseTypes = toArray(meta.response_types) ?? defaults.responseTypes;
  if (responseTypes) {
    cfg.responseTypes = responseTypes;
  }
  const scope = isNonEmptyString(meta.scope) ? meta.scope.split(/\s+/).filter(Boolean) : defaults.scope;
  if (isArray(scope)) {
    cfg.scope = scope;
  }
  if (isNonEmptyString(meta.jwks_uri)) {
    cfg.jwksUri = meta.jwks_uri;
  }
  if (isObject(meta.jwks)) {
    cfg.jwks = meta.jwks;
  }
  // Carry a couple of human-facing fields verbatim so they round-trip in the
  // response (they are not security-relevant).
  if (isNonEmptyString(meta.client_name)) {
    cfg.clientName = meta.client_name;
  }
  return cfg;
}

/**
 * @param {import('../clients.js').Client} client
 * @param {import('../clients.js').ClientConfig} cfg
 * @returns {Record<string, unknown>}
 */
function buildResponse(client, cfg) {
  /** @type {Record<string, unknown>} */
  const out = {
    client_id: client.clientId,
    client_id_issued_at: Math.floor(Date.now() / 1000),
    redirect_uris: client.redirectUris,
    grant_types: client.grantTypes,
    response_types: client.responseTypes,
    token_endpoint_auth_method: client.tokenEndpointAuthMethod,
  };
  if (isNonEmptyString(cfg.clientSecret)) {
    out.client_secret = cfg.clientSecret;
    // RFC 7591 §3.2.1: 0 means the secret does not expire.
    out.client_secret_expires_at = 0;
  }
  if (isArray(client.scope) && client.scope.length > 0) {
    out.scope = client.scope.join(' ');
  }
  if (isNonEmptyString(client.clientName)) {
    out.client_name = client.clientName;
  }
  return out;
}

// HELPERS

/** @param {unknown} value @returns {string[] | undefined} */
function toArray(value) {
  if (isArray(value)) {
    return value;
  }
  if (isNonEmptyString(value)) {
    return value.split(/\s+/).filter(Boolean);
  }
  return undefined;
}

/** @param {string | undefined} header @returns {string | undefined} */
function bearer(header) {
  if (!isNonEmptyString(header)) {
    return undefined;
  }
  const [scheme, token] = header.split(' ', 2);
  return scheme.toLowerCase() === 'bearer' && isNonEmptyString(token) ? token : undefined;
}

/** @param {string} a @param {string} b @returns {boolean} */
function constantEquals(a, b) {
  const x = Buffer.from(a, 'utf8');
  const y = Buffer.from(b, 'utf8');
  return x.length === y.length && timingSafeEqual(x, y);
}
