/**
 * `mode: 'api'` login — for a mobile app / SPA / CLI that holds the flow
 * session itself (no cookie). The start route returns JSON; the client
 * hands the opaque `session` back on the callback (RFC 8252 / AppAuth).
 *
 *   GOOGLE_ID=… GOOGLE_SECRET=… SESSION_SECRET=… node examples/login-api.mjs
 *
 *   # 1. start — the app opens `authorizeUrl` in a system browser, keeps `session`
 *   curl -X POST localhost:3000/auth/google
 *   # → { "authorizeUrl": "https://accounts.google.com/…", "session": "…" }
 *
 *   # 2. after the redirect, the app posts back the callback query + the session
 *   curl -X POST localhost:3000/auth/google/callback \
 *     -H 'content-type: application/json' \
 *     -d '{ "session": "…", "code": "…", "state": "…" }'
 *   # → { "user": { … } }
 */
import express from 'express';
import 'dotenv/config';

import { createOAuth } from '@exortek/oauth2';
import { google } from '@exortek/oauth2/providers/google';
import { oauthLogin } from '@exortek/oauth2/express';

const oauth = createOAuth({
  baseUrl: process.env.BASE_URL ?? 'http://localhost:3000',
  callback: '/auth/{provider}/callback',
  providers: [google({ clientId: process.env.GOOGLE_ID, clientSecret: process.env.GOOGLE_SECRET })],
});

const app = express();
app.use(express.json());

const login = oauthLogin({ oauth, mode: 'api', secret: process.env.SESSION_SECRET ?? 'dev-only-change-me' });

app.post('/auth/:provider', login.start); // → { authorizeUrl, session }
app.post('/auth/:provider/callback', login.callback); // body { session, ...query } → { user }

app.listen(3000, () => console.log('http://localhost:3000  (POST /auth/google)'));
