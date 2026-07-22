// Fastify API-key plugin demo.
//
//   node packages/apikey/examples/fastify-server.js
//
// Then in another terminal:
//
//   curl -s -X POST http://127.0.0.1:3000/keys \
//     -H 'content-type: application/json' \
//     -d '{"userId":"usr_123","scopes":["read"]}'
//
//   curl -s http://127.0.0.1:3000/v1/whoami \
//     -H 'Authorization: Bearer <paste-key-here>'
//
// Requires: `yarn workspace @exortek/apikey add fastify` in dev.

import Fastify from 'fastify';
import { createApiKey, mask } from '../src/index.js';
import { memoryStore } from '../src/stores/memory.js';
import { apiKeyPlugin } from '../src/middleware/fastify.js';

const store = memoryStore();
const app = Fastify({ logger: false });

// Unauthenticated key-management routes registered on the root scope.
app.post('/keys', async (req, reply) => {
  try {
    const { key, id, record } = await createApiKey({
      store,
      prefix: 'sk_live',
      userId: req.body.userId,
      scopes: req.body.scopes,
      name: req.body.name,
    });
    return { key, id, masked: mask(key), record };
  } catch (err) {
    reply.code(400);
    return { error: err.code ?? 'ERR', message: err.message };
  }
});

// Everything registered inside this scope requires a valid key.
await app.register(async scoped => {
  await scoped.register(apiKeyPlugin, {
    store,
    requiredScopes: ['read'],
    updateLastUsed: true,
  });
  scoped.get('/v1/whoami', async req => ({
    userId: req.apiKey.userId,
    scopes: req.apiKey.scopes,
    keyId: req.apiKey.id,
  }));
});

const port = Number(process.env.PORT ?? 3000);
await app.listen({ port, host: '127.0.0.1' });
// eslint-disable-next-line no-console
console.log(`apikey demo on http://127.0.0.1:${port}`);
