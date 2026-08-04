/**
 * Shared builders for the authorization-server tests. Everything is
 * hermetic — no network, in-memory stores, locally-generated keys.
 */
import { generateKeyPairSync } from 'node:crypto';

import { sign as jwtSign } from '@exortek/jwt';
import { sign as jwsSign } from '@exortek/jws';
import { exportJWK, thumbprint } from '@exortek/jwk';

import { createServer, jwtIssuer } from '../../src/server/index.js';
import { createPkcePair } from '../../src/internal/pkce.js';

export const ISSUER = 'https://as.example.com';

/** Form-url-encode an object into a request body. */
export function form(obj) {
  return new URLSearchParams(obj).toString();
}

/** A POST token/endpoint request descriptor. */
export function post(body, extraHeaders = {}) {
  return {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', ...extraHeaders },
    body: form(body),
  };
}

/** A GET authorize request descriptor. */
export function get(path, query) {
  return { method: 'GET', url: `${path}?${form(query)}` };
}

/**
 * Build a ready-to-drive server plus the AS signing keypair.
 *
 * @param {object} [overrides]  merged into the createServer config
 */
export function buildServer(overrides = {}) {
  const asKp = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const server = createServer({
    issuer: ISSUER,
    clients: overrides.clients ?? [
      {
        clientId: 'app',
        clientSecret: 's3cret-value-strong',
        tokenEndpointAuthMethod: 'client_secret_post',
        redirectUris: ['https://app.example.com/cb'],
        grantTypes: ['authorization_code', 'refresh_token', 'client_credentials'],
        scope: ['read', 'write'],
      },
    ],
    tokens: jwtIssuer({ signingKey: asKp.privateKey, verificationKey: asKp.publicKey, alg: 'ES256' }),
    authenticateUser: () => ({ subject: 'user-1' }),
    scopes: ['read', 'write', 'openid'],
    ...overrides,
  });
  return { server, asKp };
}

/**
 * Drive an authorization-code + PKCE round-trip and return the issued
 * authorization code.
 */
export async function getAuthorizationCode(
  server,
  { clientId = 'app', redirectUri = 'https://app.example.com/cb', scope, extra = {} } = {},
) {
  const pkce = createPkcePair();
  const res = await server.authorize(
    get('/authorize', {
      client_id: clientId,
      redirect_uri: redirectUri,
      response_type: 'code',
      code_challenge: pkce.codeChallenge,
      code_challenge_method: 'S256',
      ...(scope ? { scope } : {}),
      ...extra,
    }),
  );
  const location = res.headers.location;
  const code = location ? new URL(location).searchParams.get('code') : undefined;
  return { res, code, pkce, redirectUri };
}

/** A DPoP client keypair + proof factory. */
export async function dpopClient() {
  const kp = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = await exportJWK(kp.publicKey);
  const jkt = await thumbprint(jwk);
  const proof = (htm, htu) =>
    jwsSign({ jti: `${Math.random()}`, htm, htu, iat: Math.floor(Date.now() / 1000) }, kp.privateKey, {
      alg: 'ES256',
      header: { typ: 'dpop+jwt', jwk },
    });
  return { kp, jwk, jkt, proof };
}

/** A private_key_jwt client keypair + assertion factory. */
export async function assertionClient(clientId, { kid = 'k1' } = {}) {
  const kp = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = await exportJWK(kp.publicKey);
  jwk.kid = kid;
  const assertion = (jti, aud = ISSUER) =>
    jwtSign({ iss: clientId, sub: clientId, aud, jti, exp: Math.floor(Date.now() / 1000) + 60 }, kp.privateKey, {
      alg: 'ES256',
      header: { kid },
    });
  return { kp, jwk, assertion };
}

export function body(res) {
  return JSON.parse(res.body);
}
