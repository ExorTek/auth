// Express API-key middleware demo.
//
//   node packages/apikey/examples/express-server.js
//
// Then in another terminal:
//
//   # Mint a key (returns { key, id })
//   curl -s -X POST http://127.0.0.1:3000/keys \
//     -H 'content-type: application/json' \
//     -d '{"userId":"usr_123","scopes":["read","write:posts"],"name":"demo"}'
//
//   # Use it (requires the `read` scope)
//   curl -s http://127.0.0.1:3000/v1/whoami \
//     -H 'Authorization: Bearer <paste-key-here>'
//
//   # Try without a scope match — 403
//   curl -s -X POST http://127.0.0.1:3000/v1/admin \
//     -H 'Authorization: Bearer <paste-key-here>'
//
// Requires: `yarn workspace @exortek/apikey add express` in dev.

import express from 'express';
import { createApiKey, mask, revokeApiKey } from '../src/index.js';
import { memoryStore } from '../src/stores/memory.js';
import { apiKeyMiddleware } from '../src/middleware/express.js';

const store = memoryStore();

const app = express();
app.use(express.json());

// Mint / revoke live behind an unauthenticated `/keys` prefix so the
// demo works without seeding — in a real app these would be gated by
// user session auth.
app.post('/keys', async (req, res) => {
  try {
    const { key, id, record } = await createApiKey({
      store,
      prefix: 'sk_live',
      userId: req.body.userId,
      scopes: req.body.scopes,
      name: req.body.name,
      metadata: req.body.metadata,
    });
    res.json({ key, id, masked: mask(key), record });
  } catch (err) {
    res.status(400).json({ error: err.code ?? 'ERR', message: err.message });
  }
});

app.delete('/keys/:id', async (req, res) => {
  const ok = await revokeApiKey(req.params.id, { store, reason: 'demo' });
  res.json({ revoked: ok });
});

// Anything under `/v1` requires a valid API key with the `read` scope.
app.use(
  '/v1',
  apiKeyMiddleware({
    store,
    requiredScopes: ['read'],
    updateLastUsed: true,
  }),
);

app.get('/v1/whoami', (req, res) => {
  res.json({
    userId: req.apiKey.userId,
    scopes: req.apiKey.scopes,
    keyId: req.apiKey.id,
  });
});

// Extra route that demands a second scope.
app.post(
  '/v1/admin',
  apiKeyMiddleware({ store, requiredScopes: ['admin'] }),
  (req, res) => {
    res.json({ ok: true });
  },
);

const port = process.env.PORT ?? 3000;
app.listen(port, () => {
  // eslint-disable-next-line no-console
  console.log(`apikey demo on http://127.0.0.1:${port}`);
});
