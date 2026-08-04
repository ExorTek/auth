/**
 * Client authentication at the token / introspection / revocation / PAR
 * endpoints. Resolves and verifies the requesting client by the method
 * its registration declares — a client can never be downgraded to a
 * weaker method than it registered:
 *   - `none`                        public client (PKCE carries security).
 *   - `client_secret_basic`/`post`  HTTP Basic / body secret, constant-time.
 *   - `client_secret_jwt`           HS256 assertion keyed by the secret (RFC 7523).
 *   - `private_key_jwt`             asymmetric assertion, key from the client JWKS (RFC 7523).
 *   - `tls_client_auth` /
 *     `self_signed_tls_client_auth` mutual-TLS client certificate (RFC 8705).
 *
 * The assertion `aud` MUST be the AS issuer identifier, never a guessed
 * endpoint — this is the audience-injection mitigation (threat #19,
 * 2026 security-topics update), which also lets one assertion serve every
 * endpoint of the same AS.
 */
import { createHash } from 'node:crypto';

import { verify as jwtVerify, decode as jwtDecode, JwtError } from '@exortek/jwt';
import { timingSafeEqual } from '@exortek/shared/timing-safe';
import { encode as base64urlEncode } from '@exortek/shared/base64url';
import { isNonEmptyString, isObject } from '@exortek/shared/predicates';

import { ProtocolError, ServerError } from '../errors.js';
import { readClientCredentials } from '../request.js';
import { resolveClientKeys } from './client-keys.js';

const JWT_BEARER_ASSERTION = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
const ASSERTION_ALGS = new Set([
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

// Assertion replay cache — a `jti` is single-use within its lifetime.
/** @type {Map<string, number>} */
const seenAssertionJti = new Map();

/**
 * Resolve and authenticate the client behind a request.
 *
 * @param {import('../request.js').ServerRequest} req
 * @param {Record<string, any>} config
 * @returns {Promise<import('../clients.js').Client>}
 */
export async function authenticateClient(req, config) {
  // Assertion auth carries the client_id inside the signed JWT.
  const assertionType = req.form.client_assertion_type;
  if (isNonEmptyString(assertionType)) {
    return authenticateAssertion(req, config, assertionType);
  }

  const creds = readClientCredentials(req);
  const clientId = creds?.clientId ?? req.form.client_id;
  if (!isNonEmptyString(clientId)) {
    throw new ServerError(ProtocolError.INVALID_CLIENT, 'client authentication required');
  }
  const client = await config.registry.getClient(clientId);
  if (!client) {
    throw new ServerError(ProtocolError.INVALID_CLIENT, `unknown client ${JSON.stringify(clientId)}`);
  }

  // The registered method drives verification — a client can never be
  // authenticated by a weaker method than it registered (Decision #0).
  const method = client.tokenEndpointAuthMethod;
  if (method === 'none') {
    if (creds && isNonEmptyString(creds.clientSecret)) {
      throw new ServerError(ProtocolError.INVALID_CLIENT, 'public client must not present a client_secret');
    }
    return client;
  }
  if (method === 'client_secret_basic' || method === 'client_secret_post') {
    if (!creds || creds.via !== method) {
      throw new ServerError(ProtocolError.INVALID_CLIENT, `client must authenticate with ${method}`);
    }
    verifySecret(creds.clientSecret, client.clientSecret);
    return client;
  }
  if (method === 'tls_client_auth' || method === 'self_signed_tls_client_auth') {
    return authenticateByCertificate(req, client);
  }
  // private_key_jwt / client_secret_jwt registered but presented no assertion.
  throw new ServerError(ProtocolError.INVALID_CLIENT, `client ${JSON.stringify(client.clientId)} must use ${method}`);
}

/**
 * Compute the mTLS certificate-bound confirmation (`cnf.x5t#S256`) for a
 * client that authenticated with a certificate, so the issued token is
 * bound to that certificate (RFC 8705 §3). Returns `undefined` for
 * non-mTLS clients.
 *
 * @param {import('../request.js').ServerRequest} req
 * @param {import('../clients.js').Client} client
 * @returns {Record<string, string> | undefined}
 */
export function certificateConfirmation(req, client) {
  const method = client.tokenEndpointAuthMethod;
  if ((method === 'tls_client_auth' || method === 'self_signed_tls_client_auth') && isObject(req.clientCertificate)) {
    return { 'x5t#S256': certThumbprint(req.clientCertificate) };
  }
  return undefined;
}

// SECRET

/**
 * @param {string | undefined} presented
 * @param {string | undefined} registered
 */
function verifySecret(presented, registered) {
  if (!isNonEmptyString(presented) || !isNonEmptyString(registered)) {
    throw new ServerError(ProtocolError.INVALID_CLIENT, 'invalid client credentials');
  }
  const a = Buffer.from(presented, 'utf8');
  const b = Buffer.from(registered, 'utf8');
  if (a.length !== b.length || !timingSafeEqual(a, b)) {
    throw new ServerError(ProtocolError.INVALID_CLIENT, 'invalid client credentials');
  }
}

// ASSERTION (private_key_jwt / client_secret_jwt, RFC 7523)

/**
 * @param {import('../request.js').ServerRequest} req
 * @param {Record<string, any>} config
 * @param {string} assertionType
 * @returns {Promise<import('../clients.js').Client>}
 */
async function authenticateAssertion(req, config, assertionType) {
  if (assertionType !== JWT_BEARER_ASSERTION) {
    throw new ServerError(
      ProtocolError.INVALID_CLIENT,
      `unsupported client_assertion_type ${JSON.stringify(assertionType)}`,
    );
  }
  const assertion = req.form.client_assertion;
  if (!isNonEmptyString(assertion)) {
    throw new ServerError(ProtocolError.INVALID_CLIENT, 'missing client_assertion');
  }

  // Read the unverified claims only to discover which client (and thus
  // which key + method) to verify against.
  let unverified;
  try {
    unverified = jwtDecode(assertion);
  } catch {
    throw new ServerError(ProtocolError.INVALID_CLIENT, 'client_assertion is not a well-formed JWT');
  }
  const clientId = unverified?.payload?.sub;
  if (!isNonEmptyString(clientId) || unverified.payload.iss !== clientId) {
    throw new ServerError(ProtocolError.INVALID_CLIENT, 'client_assertion iss and sub must both equal the client_id');
  }

  const client = await config.registry.getClient(clientId);
  if (!client) {
    throw new ServerError(ProtocolError.INVALID_CLIENT, `unknown client ${JSON.stringify(clientId)}`);
  }

  // Resolve the verification key + alg per the registered method. These
  // pre-checks throw outside the try below, so the only exception the
  // catch handles is a genuine verification failure from `jwtVerify`.
  const method = client.tokenEndpointAuthMethod;
  const alg = unverified.header?.alg;
  /** @type {import('node:crypto').KeyObject | Buffer | Function} */
  let keyish;
  if (method === 'client_secret_jwt') {
    if (alg !== 'HS256') {
      throw new ServerError(ProtocolError.INVALID_CLIENT, 'client_secret_jwt requires HS256');
    }
    keyish = Buffer.from(client.clientSecret, 'utf8');
  } else if (method === 'private_key_jwt') {
    if (!isNonEmptyString(alg) || !ASSERTION_ALGS.has(alg)) {
      throw new ServerError(
        ProtocolError.INVALID_CLIENT,
        `private_key_jwt alg ${JSON.stringify(alg)} is not an accepted asymmetric algorithm`,
      );
    }
    keyish = await resolveClientKeys(client);
  } else {
    throw new ServerError(
      ProtocolError.INVALID_CLIENT,
      `client ${JSON.stringify(clientId)} is not registered for assertion authentication`,
    );
  }

  let payload;
  try {
    // aud MUST be the issuer identifier (threat #19) — jwtVerify enforces it.
    ({ payload } = await jwtVerify(assertion, keyish, { alg: [alg], audience: config.issuer }));
  } catch (err) {
    if (err instanceof JwtError) {
      throw new ServerError(ProtocolError.INVALID_CLIENT, 'client_assertion verification failed');
    }
    throw err;
  }

  assertSingleUse(payload.jti);
  return client;
}

/** @param {unknown} jti */
function assertSingleUse(jti) {
  if (!isNonEmptyString(jti)) {
    throw new ServerError(ProtocolError.INVALID_CLIENT, 'client_assertion is missing jti');
  }
  const now = Date.now();
  if (seenAssertionJti.size > 1024) {
    for (const [id, exp] of seenAssertionJti) {
      if (exp <= now) {
        seenAssertionJti.delete(id);
      }
    }
  }
  if (seenAssertionJti.has(jti)) {
    throw new ServerError(ProtocolError.INVALID_CLIENT, 'client_assertion jti has already been used (replay)');
  }
  // Assertions are short-lived; a 5-minute retention covers any sane exp.
  seenAssertionJti.set(jti, now + 300_000);
}

// mTLS (RFC 8705)

/**
 * @param {import('../request.js').ServerRequest} req
 * @param {import('../clients.js').Client} client
 * @returns {Promise<import('../clients.js').Client>}
 */
async function authenticateByCertificate(req, client) {
  const cert = req.clientCertificate;
  if (!isObject(cert)) {
    throw new ServerError(ProtocolError.INVALID_CLIENT, 'mTLS client authentication requires a client certificate');
  }

  if (client.tokenEndpointAuthMethod === 'tls_client_auth') {
    // PKI mTLS: the certificate's subject DN must match the registered
    // expected value (RFC 8705 §2.1).
    const subject = certSubjectString(cert);
    if (!isNonEmptyString(client.tlsClientAuthSubjectDn) || client.tlsClientAuthSubjectDn !== subject) {
      throw new ServerError(
        ProtocolError.INVALID_CLIENT,
        'client certificate subject does not match the registered value',
      );
    }
    return client;
  }
  if (client.tokenEndpointAuthMethod === 'self_signed_tls_client_auth') {
    // Self-signed mTLS: the certificate thumbprint must be present in the
    // client's registered JWKS (RFC 8705 §2.2).
    const thumb = certThumbprint(cert);
    if (!certInJwks(client, thumb)) {
      throw new ServerError(ProtocolError.INVALID_CLIENT, 'client certificate is not registered for this client');
    }
    return client;
  }
  throw new ServerError(
    ProtocolError.INVALID_CLIENT,
    `client ${JSON.stringify(client.clientId)} is not registered for mTLS`,
  );
}

/**
 * @param {object} cert   a Node TLS PeerCertificate (or a compatible shape)
 * @returns {string} base64url SHA-256 of the DER certificate (`x5t#S256`)
 */
function certThumbprint(cert) {
  const der = /** @type {any} */ (cert).raw;
  if (der === undefined) {
    throw new ServerError(ProtocolError.INVALID_CLIENT, 'client certificate has no DER encoding to fingerprint');
  }
  return base64urlEncode(createHash('sha256').update(der).digest());
}

/** @param {object} cert @returns {string} */
function certSubjectString(cert) {
  const subject = /** @type {any} */ (cert).subject;
  if (isNonEmptyString(subject)) {
    return subject;
  }
  if (isObject(subject)) {
    // Node parses the subject into an object; render a stable DN string.
    return Object.entries(subject)
      .map(([k, v]) => `${k}=${v}`)
      .join(',');
  }
  throw new ServerError(ProtocolError.INVALID_CLIENT, 'client certificate has no subject');
}

/**
 * @param {import('../clients.js').Client} client
 * @param {string} thumb
 * @returns {boolean}
 */
function certInJwks(client, thumb) {
  if (isNonEmptyString(client.certificateThumbprint)) {
    return client.certificateThumbprint === thumb;
  }
  return false;
}
