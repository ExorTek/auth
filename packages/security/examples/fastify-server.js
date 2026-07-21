// Fastify security plugin demo.
//
//   node packages/security/examples/fastify-server.js
//
//   curl -i http://127.0.0.1:3001/ping
//   for i in {1..12}; do curl -s -o /dev/null -w "%{http_code}\n" \
//     http://127.0.0.1:3001/ping; done   # last few should be 429
//
// Requires: `yarn workspace @exortek/security add fastify @fastify/cookie` in dev.

import Fastify from 'fastify';
import fastifyCookie from '@fastify/cookie';
import { rateLimit } from '../src/index.js';
import { securityPlugin } from '../src/middleware/fastify.js';

const SECRET = 'x'.repeat(32);

const app = Fastify({ trustProxy: true });
await app.register(fastifyCookie);
await app.register(securityPlugin, {
  cors: { origin: ['https://app.example.com'] },
  csrf: { secret: SECRET },
  rateLimit: {
    limiter: rateLimit.sliding({
      requests: 10,
      window: '1m',
      store: rateLimit.stores.memory(),
    }),
  },
});

app.get('/ping', async () => ({ ok: true }));
app.post('/api/echo', async req => ({ echo: req.body ?? null }));

const port = Number(process.env.PORT) || 3001;
await app.listen({ port, host: '127.0.0.1' });
console.log(`fastify security demo → http://127.0.0.1:${port}`);
