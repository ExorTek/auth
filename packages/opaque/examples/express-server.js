// Express opaque-token demo — create/introspect/revoke over HTTP.
//
//   node packages/opaque/examples/express-server.js
//
// Then in another terminal:
//
//   # Mint a token (returns { token, hash, expiresAt })
//   curl -s -X POST http://127.0.0.1:3000/tokens \
//     -H 'content-type: application/json' \
//     -d '{"userId":"usr_123","scope":"read write"}' -o /tmp/tok.json
//   TOKEN=$(node -e "console.log(JSON.parse(require('fs').readFileSync('/tmp/tok.json')).token)")
//
//   # RFC 7662 — introspect it
//   curl -s -X POST http://127.0.0.1:3000/oauth/introspect \
//     -H 'content-type: application/json' -d "{\"token\":\"$TOKEN\"}"
//
//   # RFC 7009 — revoke it, then introspect again (now active: false)
//   curl -s -X POST http://127.0.0.1:3000/oauth/revoke \
//     -H 'content-type: application/json' -d "{\"token\":\"$TOKEN\"}"
//
// Requires: `yarn workspace @exortek/opaque add express` in dev.

import express from 'express';
import { create, introspectionHandler, revocationHandler, OpaqueError } from '../src/index.js';
import { memoryStore } from '../src/stores/memory.js';

const store = memoryStore();

const app = express();
app.use(express.json());

// Mint route lives behind an unauthenticated prefix so the demo works
// without seeding — in a real app this would be gated by your own
// login/consent flow (this is the "issue an access token" step).
app.post('/tokens', async (req, res) => {
  try {
    const { token, hash, expiresAt } = await create({
      format: 'hex',
      store,
      expiresIn: '1h',
      metadata: { userId: req.body.userId, scope: req.body.scope },
    });
    res.json({ token, hash, expiresAt });
  } catch (err) {
    // Only echo the message for our own errors (deterministic, safe to
    // share). Anything else may include a stack frame or env detail —
    // let the framework's default handler log it and return a generic 500.
    if (err instanceof OpaqueError) {
      return res.status(400).json({ error: err.code, message: err.message });
    }
    throw err;
  }
});

// Handlers now return { status, body } — the caller owns the response.
// Add CORS headers, envelope the body, whatever — the handler stays out
// of the response object entirely.
const introspect = introspectionHandler({ store });
const revokeRoute = revocationHandler({ store });

app.post('/oauth/introspect', async (req, res) => {
  const { status, body, headers } = await introspect(req);
  res.set(headers).status(status).json(body);
});

app.post('/oauth/revoke', async (req, res) => {
  const { status, body, headers } = await revokeRoute(req);
  res.set(headers).status(status).json(body);
});

const port = Number(process.env.PORT ?? 3000);
app.listen(port, () => console.log(`opaque demo on http://127.0.0.1:${port}`));
