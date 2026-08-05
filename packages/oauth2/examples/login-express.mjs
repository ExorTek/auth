/**
 * Relying-party login on Express — "log in with Google / GitHub".
 *
 *   GOOGLE_ID=… GOOGLE_SECRET=… GITHUB_ID=… GITHUB_SECRET=… \
 *   SESSION_SECRET=… node examples/login-express.mjs
 *
 * Open http://localhost:3000/auth/google to start the flow.
 */
import express from 'express';

import { createOAuth } from '@exortek/oauth2';
import { google } from '@exortek/oauth2/providers/google';
import { github } from '@exortek/oauth2/providers/github';
import { oauthLogin } from '@exortek/oauth2/express';

const oauth = createOAuth({
  baseUrl: process.env.BASE_URL ?? 'http://localhost:3000',
  callback: '/auth/{provider}/callback',
  providers: [
    google({ clientId: process.env.GOOGLE_ID, clientSecret: process.env.GOOGLE_SECRET }),
    github({ clientId: process.env.GITHUB_ID, clientSecret: process.env.GITHUB_SECRET }),
  ],
});

const app = express();

// `web` mode: the flow session rides a signed, httpOnly cookie. Drop the
// two handlers onto your own routes — the passport-style factory.
const login = oauthLogin({
  oauth,
  cookie: { secret: process.env.SESSION_SECRET ?? 'dev-only-change-me' },
  onSuccess: ({ res, user }) => {
    // Here you'd create YOUR session for `user`. For the demo, echo it.
    res.json({ loggedInAs: user });
  },
  onError: ({ res, error }) => res.status(400).json({ error: error.code ?? 'login_failed' }),
});

app.get('/auth/:provider', login.start); // → 302 to the provider
app.get('/auth/:provider/callback', login.callback); // → onSuccess

app.get('/', (_req, res) => res.type('html').send('<a href="/auth/google">Log in with Google</a>'));

app.listen(3000, () => console.log('http://localhost:3000'));
