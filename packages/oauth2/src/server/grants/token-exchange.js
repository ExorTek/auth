/**
 * Token Exchange grant (RFC 8693) — delegation / impersonation for
 * service chains. A client presents a `subject_token` it already holds
 * and exchanges it for a new access token, optionally scoped down and
 * re-audienced for a downstream `resource`/`audience`. The subject token
 * is validated through the issuer strategy; a valid one yields a token
 * for the same subject, never a privilege escalation:
 *   - the subject token must have been issued to the exchanging client,
 *     name it in `aud`, or permit it through `may_act` (RFC 8693 §4.4) —
 *     a token picked up elsewhere cannot be laundered into a fresh one;
 *   - a sender-constrained subject token (`cnf`) is exchanged only by the
 *     holder of the bound key / certificate;
 *   - scope only narrows, and stays within the exchanger's own ceiling;
 *   - the target audience must be on `tokenExchange.audiences`.
 */
import { isArray, isNonEmptyString, isObject } from '@exortek/shared/predicates';

import { ProtocolError, ServerError } from '../errors.js';
import { validateResource } from '../security/resource.js';
import { assertWithinCeiling, parseScope, scopeCeiling } from '../security/scope.js';
import { buildAccessResponse } from './_issue.js';

const ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';

/**
 * @param {import('../request.js').ServerRequest} req
 * @param {{ config: Record<string, any>, client: import('../clients.js').Client, dpopJkt?: string }} ctx
 * @returns {Promise<Record<string, unknown>>}
 */
export async function tokenExchangeGrant(req, ctx) {
  const { config, client } = ctx;

  if (!client.grantTypes.includes('urn:ietf:params:oauth:grant-type:token-exchange')) {
    throw new ServerError(ProtocolError.UNAUTHORIZED_CLIENT, 'client may not use token exchange');
  }

  const subjectToken = req.form.subject_token;
  const subjectTokenType = req.form.subject_token_type;
  if (!isNonEmptyString(subjectToken) || !isNonEmptyString(subjectTokenType)) {
    throw new ServerError(ProtocolError.INVALID_REQUEST, 'subject_token and subject_token_type are required');
  }
  // v1 exchanges an access token; other subject token types are a future
  // extension rather than a silent accept.
  if (subjectTokenType !== ACCESS_TOKEN_TYPE) {
    throw new ServerError(
      ProtocolError.INVALID_REQUEST,
      `unsupported subject_token_type ${JSON.stringify(subjectTokenType)}`,
    );
  }

  const { active, claims } = await config.tokens.introspect(subjectToken, { issuer: config.issuer });
  if (!active || !claims || !isNonEmptyString(claims.sub)) {
    throw new ServerError(ProtocolError.INVALID_GRANT, 'subject_token is not valid');
  }

  assertMayExchange(claims, client);
  assertHolderOfKey(claims, ctx);

  const grantedScope = parseScope(claims.scope);
  const ceiling = scopeCeiling(client, config);
  let scope;
  if (isNonEmptyString(req.form.scope)) {
    scope = narrowScope(req.form.scope, grantedScope);
    assertWithinCeiling(scope, ceiling);
  } else {
    scope = isArray(ceiling) ? grantedScope.filter(s => ceiling.includes(s)) : grantedScope;
  }
  const audience = resolveTarget(req.form.resource, req.form.audience, config);

  const body = await buildAccessResponse(config, {
    subject: claims.sub,
    clientId: client.clientId,
    scope,
    audience,
    dpopJkt: ctx.dpopJkt,
    confirmation: ctx.confirmation,
    // RFC 8693 §4.1: the current actor is the top-level `act`; any prior
    // actor chain from the subject token nests beneath it.
    extra: { act: isObject(claims.act) ? { sub: client.clientId, act: claims.act } : { sub: client.clientId } },
  });
  // RFC 8693 §2.2.1 requires issued_token_type on the response.
  body.issued_token_type = ACCESS_TOKEN_TYPE;
  return body;
}

/**
 * @param {string | undefined} requested
 * @param {string[]} granted
 * @returns {string[]}
 */
function narrowScope(requested, granted) {
  if (!isNonEmptyString(requested)) {
    return granted;
  }
  const asked = requested.split(/\s+/).filter(Boolean);
  for (const s of asked) {
    if (!granted.includes(s)) {
      throw new ServerError(
        ProtocolError.INVALID_SCOPE,
        `scope ${JSON.stringify(s)} exceeds the subject token's scope`,
      );
    }
  }
  return asked;
}

/**
 * The exchanging client must be the subject token's own client, one of its
 * audiences, or the actor its `may_act` claim authorizes.
 *
 * @param {Record<string, any>} claims
 * @param {import('../clients.js').Client} client
 */
function assertMayExchange(claims, client) {
  const id = client.clientId;
  const audiences = isArray(claims.aud) ? claims.aud : [claims.aud];
  const mayAct = isObject(claims.may_act) ? claims.may_act : undefined;
  if (claims.client_id === id || audiences.includes(id) || mayAct?.client_id === id || mayAct?.sub === id) {
    return;
  }
  throw new ServerError(ProtocolError.INVALID_GRANT, 'subject_token was not issued to or for this client');
}

/**
 * A sender-constrained subject token can only be exchanged by a request
 * that proves the same key (DPoP `cnf.jkt`, RFC 9449) or certificate
 * (`cnf.x5t#S256`, RFC 8705) — otherwise exchanging would strip the
 * binding off a stolen token.
 *
 * @param {Record<string, any>} claims
 * @param {{ dpopJkt?: string, confirmation?: Record<string, string> }} ctx
 */
function assertHolderOfKey(claims, ctx) {
  if (!isObject(claims.cnf)) {
    return;
  }
  const { jkt } = claims.cnf;
  const x5t = claims.cnf['x5t#S256'];
  if (isNonEmptyString(jkt) && ctx.dpopJkt !== jkt) {
    throw new ServerError(
      ProtocolError.INVALID_GRANT,
      'subject_token is DPoP-bound to a key this request did not prove',
    );
  }
  if (isNonEmptyString(x5t) && ctx.confirmation?.['x5t#S256'] !== x5t) {
    throw new ServerError(
      ProtocolError.INVALID_GRANT,
      'subject_token is bound to a client certificate this request did not present',
    );
  }
}

/**
 * The exchange target — a `resource` URI (RFC 8707) or an `audience`
 * identifier (RFC 8693). A malformed `resource` is `invalid_target`, and so
 * is any target missing from `tokenExchange.audiences`: without an
 * allowlist, a token can only be exchanged for one addressed to the client.
 *
 * @param {string | undefined} resource
 * @param {string | undefined} audience
 * @param {Record<string, any>} config
 * @returns {string | undefined}
 */
function resolveTarget(resource, audience, config) {
  let target;
  if (isNonEmptyString(resource)) {
    target = validateResource(resource);
  } else if (isNonEmptyString(audience)) {
    target = audience;
  } else {
    return undefined;
  }
  const allowed = config.tokenExchange?.audiences;
  if (!isArray(allowed) || !allowed.includes(target)) {
    throw new ServerError(ProtocolError.INVALID_TARGET, `exchange target ${JSON.stringify(target)} is not permitted`);
  }
  return target;
}
