/**
 * Relying-party login on Fastify — the same flow as login-express.mjs.
 *
 *   GOOGLE_ID=… GOOGLE_SECRET=… SESSION_SECRET=… node examples/login-fastify.mjs
 *
 * Open http://localhost:3000/auth/google to start the flow.
 */
import Fastify from 'fastify';
import 'dotenv/config';

import { createOAuth } from '@exortek/oauth2';
import { google } from '@exortek/oauth2/providers/google';
import { oauthLoginPlugin } from '@exortek/oauth2/fastify';

const oauth = createOAuth({
  baseUrl: process.env.BASE_URL ?? 'http://localhost:3000',
  callback: '/auth/{provider}/callback',
  providers: [google({ clientId: process.env.GOOGLE_ID, clientSecret: process.env.GOOGLE_SECRET })],
});

const app = Fastify();

// Route-scoped plugin: registers GET /auth/:provider and the callback,
// nothing app-wide.
await app.register(oauthLoginPlugin, {
  oauth,
  cookie: { secret: process.env.SESSION_SECRET ?? 'dev-only-change-me' },
  onSuccess: ({ reply, user }) => reply.send({ loggedInAs: user }),
  onError: ({ reply, error }) => reply.status(400).send({ error: error.code ?? 'login_failed' }),
});

app.get('/', (_req, reply) => reply.type('text/html').send('<a href="/auth/google">Log in with Google</a>'));

await app.listen({ port: 3000 });
console.log('http://localhost:3000');
