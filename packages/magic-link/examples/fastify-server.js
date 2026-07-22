// Fastify magic-link demo.
//
//   node packages/magic-link/examples/fastify-server.js
//
// Then in another terminal:
//
//   curl -s -X POST http://127.0.0.1:3000/auth/request \
//     -H 'content-type: application/json' \
//     -d '{"email":"user@example.com"}'
//   # copy the URL printed in server logs
//   curl -si "<paste-url-from-server-log>"
//
// Requires: `yarn workspace @exortek/magic-link add fastify` in dev.

import Fastify from 'fastify';
import { createMagicLink, verifyMagicLink } from '../src/index.js';
import { memoryStore } from '../src/stores/memory.js';

const SECRET = 'x'.repeat(32);
const BASE_URL = 'http://127.0.0.1:3000/auth/verify';

const store = memoryStore();
const app = Fastify({ logger: false });

app.post('/auth/request', async (req, reply) => {
  const { email } = req.body ?? {};
  if (!email) {
    reply.code(400);
    return { error: 'email required' };
  }
  try {
    const { url, id } = await createMagicLink({
      secret: SECRET,
      email,
      baseUrl: BASE_URL,
      expiresIn: '15m',
      redirectTo: '/dashboard',
      store,
      maxPerEmail: { count: 5, window: '1h' },
    });
    // eslint-disable-next-line no-console
    console.log(`[demo] magic link for ${email}: ${url}`);
    return { ok: true, id, hint: 'check server logs for the URL' };
  } catch (err) {
    if (err.code === 'RATE_LIMITED') {
      reply.code(429);
      return { error: err.code };
    }
    reply.code(400);
    return { error: err.code ?? 'ERR', message: err.message };
  }
});

app.get('/auth/verify', async (req, reply) => {
  const result = await verifyMagicLink(req.query.token, {
    secret: SECRET,
    store,
  });
  if (!result.valid) {
    reply.code(401);
    return { error: result.reason };
  }
  return {
    ok: true,
    email: result.email,
    redirectTo: result.redirectTo,
  };
});

const port = Number(process.env.PORT ?? 3000);
await app.listen({ port, host: '127.0.0.1' });
// eslint-disable-next-line no-console
console.log(`magic-link demo on http://127.0.0.1:${port}`);
