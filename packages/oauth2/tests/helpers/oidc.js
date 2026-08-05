/**
 * Hermetic OIDC test rig — a locally-signed id_token plus a stub
 * authorization server that serves the matching JWKS, discovery
 * document, token, and userinfo endpoints. No network, no live provider
 * (PLAN.md testing strategy).
 */
import { createServer } from 'node:http';

import { generate } from '@exortek/jwk/generate';
import { sign } from '@exortek/jwt';

/**
 * Generate an EC P-256 signing key and return a signer plus its public
 * JWK (for the stub JWKS).
 */
export async function makeSigner({ kid = 'test-key-1', alg = 'ES256' } = {}) {
  const { publicJwk, privateJwk } = await generate('EC', { curve: 'P-256', kid, alg, use: 'sig' });

  /**
   * @param {Record<string, unknown>} claims
   * @param {import('@exortek/jwt').SignOptions} [opts]
   */
  const mint = (claims, opts = {}) => sign(claims, privateJwk, { alg, kid, ...opts });

  return { publicJwk, mint, kid, alg };
}

/**
 * Start a stub AS. Pass the public JWK(s) to publish and per-endpoint
 * handlers. Returns `{ base, jwksUri, close }` and the resolved issuer.
 *
 * @param {{
 *   publicJwks: object[],
 *   token?: (body: URLSearchParams) => object,
 *   userinfo?: (auth: string | undefined) => object,
 *   extraDiscovery?: object,
 * }} config
 */
export async function startStubAS(config) {
  const { publicJwks, token, userinfo, extraDiscovery } = config;
  // Declared before the handler so the discovery route never hits it in the
  // temporal dead zone (a request landing between listen() and the assignment).
  let base = '';
  const server = createServer((req, res) => {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const json = (status, body) => {
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(JSON.stringify(body));
    };

    if (url.pathname === '/.well-known/jwks.json') {
      return json(200, { keys: publicJwks });
    }
    if (url.pathname === '/.well-known/openid-configuration') {
      return json(200, {
        issuer: base,
        authorization_endpoint: `${base}/authorize`,
        token_endpoint: `${base}/token`,
        userinfo_endpoint: `${base}/userinfo`,
        jwks_uri: `${base}/.well-known/jwks.json`,
        ...extraDiscovery,
      });
    }
    if (url.pathname === '/token' && req.method === 'POST') {
      const chunks = [];
      req.on('data', c => chunks.push(c));
      req.on('end', () => {
        const body = new URLSearchParams(Buffer.concat(chunks).toString());
        json(200, token ? token(body) : { access_token: 'at', token_type: 'Bearer' });
      });
      return;
    }
    if (url.pathname === '/userinfo') {
      return json(200, userinfo ? userinfo(req.headers.authorization) : {});
    }
    json(404, { error: 'not_found' });
  });

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const { port } = /** @type {import('node:net').AddressInfo} */ (server.address());
  base = `http://127.0.0.1:${port}`;

  return {
    base,
    issuer: base,
    jwksUri: `${base}/.well-known/jwks.json`,
    close: () => new Promise(resolve => server.close(resolve)),
  };
}
