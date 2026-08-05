/**
 * CREATE your own provider with `defineProvider` — for any OIDC issuer
 * that has no built-in preset (Keycloak, Auth0, Zitadel, Okta org, a
 * corporate IdP…). `discover: true` resolves the endpoints from the
 * issuer's /.well-known/openid-configuration, so you only give the issuer
 * URL + how to map the claims to your user.
 *
 *   ISSUER=https://your-tenant.auth0.com \
 *   CLIENT_ID=… CLIENT_SECRET=… \
 *     node examples/custom-provider.mjs
 *   open http://localhost:5300
 *
 * Register this redirect URI on the IdP:
 *   http://localhost:5300/auth/acme/callback
 */
import express from 'express';
import 'dotenv/config';

import { createOAuth, defineProvider } from '@exortek/oauth2';
import { oauthLogin } from '@exortek/oauth2/express';

const PORT = 5300;
const BASE = `http://localhost:${PORT}`;
const { ISSUER, CLIENT_ID, CLIENT_SECRET } = process.env;
if (!ISSUER || !CLIENT_ID || !CLIENT_SECRET) {
  console.error('Set ISSUER, CLIENT_ID and CLIENT_SECRET env vars first.');
  process.exit(1);
}

// This is exactly how the built-in presets (google, github, …) are made —
// a descriptor + a factory. `discover: true` fetches the endpoints; drop
// it and pass authorizationEndpoint / tokenEndpoint / jwksUri yourself.
const acme = defineProvider({
  id: 'acme',
  kind: 'oidc',
  issuer: ISSUER,
  discover: true,
  defaultScopes: ['openid', 'email', 'profile'],
  // Shape the provider's raw claims into your app's user object.
  mapUser: raw => ({ sub: raw.sub, email: raw.email, name: raw.name }),
});

const oauth = createOAuth({
  baseUrl: BASE,
  callback: '/auth/{provider}/callback',
  providers: [acme({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET })],
});

const app = express();
const login = oauthLogin({
  oauth,
  cookie: { secret: 'dev-only-change-me' },
  onSuccess: ({ res, user }) =>
    res.type('html').send(`✅ logged in as ${user.email ?? user.sub}<pre>${JSON.stringify(user, null, 2)}</pre>`),
  onError: ({ res, error }) => res.status(400).send(`❌ ${error.code ?? error.message}`),
});

app.get('/auth/:provider', login.start);
app.get('/auth/:provider/callback', login.callback);
app.get('/', (_req, res) => res.type('html').send('<a href="/auth/acme">Log in with your custom OIDC provider</a>'));

app.listen(PORT, () => console.log(`${BASE}\nregister redirect: ${BASE}/auth/acme/callback`));
