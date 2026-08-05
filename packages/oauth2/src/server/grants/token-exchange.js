/**
 * Token Exchange grant (RFC 8693) — delegation / impersonation for
 * service chains. A client presents a `subject_token` it already holds
 * and exchanges it for a new access token, optionally scoped down and
 * re-audienced for a downstream `resource`/`audience`. The subject token
 * is validated through the issuer strategy; a valid one yields a token
 * for the same subject, never a privilege escalation (scope can only
 * narrow, audience must be an authorized target).
 */
import { isNonEmptyString } from '@exortek/shared/predicates';

import { ProtocolError, ServerError } from '../errors.js';
import { validateResource } from '../security/resource.js';
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

  const grantedScope = isNonEmptyString(claims.scope) ? claims.scope.split(/\s+/).filter(Boolean) : [];
  const scope = narrowScope(req.form.scope, grantedScope);
  const audience = resolveTarget(req.form.resource, req.form.audience);

  const body = await buildAccessResponse(config, {
    subject: claims.sub,
    clientId: client.clientId,
    scope,
    audience,
    dpopJkt: ctx.dpopJkt,
    // RFC 8693 §4.1: record the acting party in the issued token.
    extra: { act: { sub: client.clientId } },
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
 * The exchange target — a `resource` URI (RFC 8707) or an `audience`
 * identifier (RFC 8693). A malformed `resource` is `invalid_target`.
 *
 * @param {string | undefined} resource
 * @param {string | undefined} audience
 * @returns {string | undefined}
 */
function resolveTarget(resource, audience) {
  if (isNonEmptyString(resource)) {
    return validateResource(resource);
  }
  if (isNonEmptyString(audience)) {
    return audience;
  }
  return undefined;
}
