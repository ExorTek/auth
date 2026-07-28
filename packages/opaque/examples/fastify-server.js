// Fastify opaque-token demo — create/introspect/revoke over HTTP.
//
//   node packages/opaque/examples/fastify-server.js
//
// Then in another terminal:
//
//   curl -s -X POST http://127.0.0.1:3000/tokens \
//     -H 'content-type: application/json' \
//     -d '{"userId":"usr_123","scope":"read"}'
//
//   curl -s -X POST http://127.0.0.1:3000/oauth/introspect \
//     -H 'content-type: application/json' -d '{"token":"<paste-token-here>"}'
//
//   curl -s -X POST http://127.0.0.1:3000/oauth/revoke \
//     -H 'content-type: application/json' -d '{"token":"<paste-token-here>"}'
//
// Requires: `yarn workspace @exortek/opaque add fastify` in dev.

import Fastify from 'fastify';
import { create, introspectionHandler, revocationHandler } from '../src/index.js';
import { memoryStore } from '../src/stores/memory.js';

const store = memoryStore();
const app = Fastify({ logger: false });

app.post('/tokens', async (req, reply) => {
  try {
    const { token, hash, expiresAt } = await create({
      format: 'hex',
      store,
      expiresIn: '1h',
      metadata: { userId: req.body.userId, scope: req.body.scope },
    });
    return { token, hash, expiresAt };
  } catch (err) {
    reply.code(400);
    return { error: err.code ?? 'ERR', message: err.message };
  }
});

app.post('/oauth/introspect', introspectionHandler({ store }));
app.post('/oauth/revoke', revocationHandler({ store }));

const port = Number(process.env.PORT ?? 3000);
await app.listen({ port, host: '127.0.0.1' });
// eslint-disable-next-line no-console
console.log(`opaque demo on http://127.0.0.1:${port}`);
