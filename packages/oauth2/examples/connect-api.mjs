/**
 * "Connect your account" — request an API scope at login and use the
 * returned access token to call the provider's API. Same flow as a plain
 * login; the difference is the scope and that you keep `tokens`.
 *
 * This demo connects Google Drive AND GitHub repos, then lists them.
 *
 *   GOOGLE_ID=… GOOGLE_SECRET=… GITHUB_ID=… GITHUB_SECRET=… \
 *   SESSION_SECRET=… node examples/connect-api.mjs
 *   open http://localhost:5300
 *
 * Register these redirect URIs:
 *   http://localhost:5300/connect/google/callback
 *   http://localhost:5300/connect/github/callback
 */
import express from 'express';
import 'dotenv/config';

import { createOAuth } from '@exortek/oauth2';
import { google } from '@exortek/oauth2/providers/google';
import { github } from '@exortek/oauth2/providers/github';
import { oauthLogin } from '@exortek/oauth2/express';

const BASE = 'http://localhost:5300';

const oauth = createOAuth({
  baseUrl: BASE,
  callback: '/connect/{provider}/callback',
  providers: [
    // Drive read scope → the access token can call the Drive API.
    google({
      clientId: process.env.GOOGLE_ID,
      clientSecret: process.env.GOOGLE_SECRET,
      scope: ['openid', 'email', 'https://www.googleapis.com/auth/drive.readonly'],
    }),
    // repo scope → the token can list the user's repositories.
    github({
      clientId: process.env.GITHUB_ID,
      clientSecret: process.env.GITHUB_SECRET,
      scope: ['read:user', 'user:email', 'repo'],
    }),
  ],
});

const app = express();

const connect = oauthLogin({
  oauth,
  cookie: { secret: process.env.SESSION_SECRET ?? 'dev-only-change-me' },
  onSuccess: async ({ req, res, user, tokens }) => {
    const provider = req.params.provider;
    let items = [];
    if (provider === 'google') {
      const r = await fetch('https://www.googleapis.com/drive/v3/files?pageSize=10', {
        headers: { authorization: `Bearer ${tokens.access_token}` },
      }).then(x => x.json());
      items = (r.files ?? []).map(f => f.name);
    } else if (provider === 'github') {
      const r = await fetch('https://api.github.com/user/repos?per_page=10', {
        headers: { authorization: `Bearer ${tokens.access_token}`, 'user-agent': 'exortek-connect-demo' },
      }).then(x => x.json());
      items = Array.isArray(r) ? r.map(repo => repo.full_name) : [];
    }
    res
      .type('html')
      .send(
        `<h2>✅ Connected ${provider} as ${user.email ?? user.sub}</h2>` +
          `<p>First items from their API:</p><ul>${items.map(i => `<li>${i}</li>`).join('')}</ul>` +
          `<a href="/">← back</a>`,
      );
  },
  onError: ({ res, error }) => res.status(400).send(`❌ ${error.code ?? error.message}`),
});

app.get('/connect/:provider', connect.start);
app.get('/connect/:provider/callback', connect.callback);
app.get('/', (_req, res) =>
  res
    .type('html')
    .send('<a href="/connect/google">Connect Google Drive</a><br><a href="/connect/github">Connect GitHub repos</a>'),
);

app.listen(5300, () => console.log(`${BASE}`));
