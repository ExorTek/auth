/**
 * A minimal OAuth 2.1 authorization server on Express — `createServer`.
 *
 *   node examples/server-express.mjs
 *
 * Then, as the `demo` client (PKCE required):
 *   open http://localhost:4000/authorize?response_type=code&client_id=demo\
 *     &redirect_uri=http://localhost:5173/cb&code_challenge=<S256>&code_challenge_method=S256
 *
 * Metadata: http://localhost:4000/.well-known/oauth-authorization-server
 */
import { generateKeyPairSync } from 'node:crypto';
import express from 'express';

import { createServer, jwtIssuer } from '@exortek/oauth2/server';
import { mountOAuth2Server } from '@exortek/oauth2/server/express';

// The AS signing key (rotate / load from KMS in production).
const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });

const server = createServer({
  issuer: process.env.ISSUER ?? 'http://localhost:4000',
  clients: [
    {
      clientId: 'demo',
      // A public SPA client: no secret, PKCE carries the proof.
      tokenEndpointAuthMethod: 'none',
      redirectUris: ['http://localhost:5173/cb'],
      grantTypes: ['authorization_code', 'refresh_token'],
      scope: ['openid', 'profile'],
    },
  ],
  scopes: ['openid', 'profile'],
  tokens: jwtIssuer({ signingKey: privateKey, verificationKey: publicKey, alg: 'ES256' }),
  // Your login + consent UI decides who the user is. For the demo we
  // pretend the request already carries an authenticated user.
  authenticateUser: () => ({ subject: 'user-123' }),
});

const app = express();
app.use(express.urlencoded({ extended: false }));

mountOAuth2Server(app, server);
// Mounts: /authorize /token /revoke /introspect /par /device_authorization
// + /.well-known/oauth-authorization-server (+ openid-configuration)

app.listen(4000, () => console.log('AS on http://localhost:4000'));
