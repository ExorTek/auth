// Express magic-link demo.
//
//   node packages/magic-link/examples/express-server.js
//
// Then in another terminal:
//
//   # Request a magic link (would be an email — here it prints the URL)
//   curl -s -X POST http://127.0.0.1:3000/auth/request \
//     -H 'content-type: application/json' \
//     -d '{"email":"user@example.com"}'
//
//   # Copy the printed url + open in browser, or:
//   curl -si "<paste-url-from-server-log>"
//
// Requires: `yarn workspace @exortek/magic-link add express` in dev.

import express from 'express';
import { createMagicLink, verifyMagicLink } from '../src/index.js';
import { memoryStore } from '../src/stores/memory.js';

const SECRET = 'x'.repeat(32); // demo only — read from env in prod
const BASE_URL = 'http://127.0.0.1:3000/auth/verify';

const store = memoryStore();

const app = express();
app.use(express.json());

// POST /auth/request — the user submits their email.
app.post('/auth/request', async (req, res) => {
  const { email } = req.body ?? {};
  if (!email) return res.status(400).json({ error: 'email required' });
  try {
    const { url, id } = await createMagicLink({
      secret: SECRET,
      email,
      baseUrl: BASE_URL,
      expiresIn: '15m',
      redirectTo: '/dashboard',
      metadata: { requestedAt: new Date().toISOString() },
      store,
      maxPerEmail: { count: 5, window: '1h' },
    });
    // In prod: await mailer.send(email, `Sign in: ${url}`)
    // For the demo, print it to the server log so curl can grab it.
    // eslint-disable-next-line no-console
    console.log(`[demo] magic link for ${email}: ${url}`);
    res.json({ ok: true, id, hint: 'check server logs for the URL' });
  } catch (err) {
    if (err.code === 'RATE_LIMITED') return res.status(429).json({ error: err.code });
    res.status(400).json({ error: err.code ?? 'ERR', message: err.message });
  }
});

// GET /auth/verify?token=... — the click.
app.get('/auth/verify', async (req, res) => {
  const result = await verifyMagicLink(req.query.token, {
    secret: SECRET,
    store,
  });
  if (!result.valid) {
    return res.status(401).json({ error: result.reason });
  }
  // In a real app: issue a session cookie / JWT here.
  res.json({
    ok: true,
    email: result.email,
    redirectTo: result.redirectTo,
    metadata: result.metadata,
  });
});

const port = process.env.PORT ?? 3000;
app.listen(port, () => {
  // eslint-disable-next-line no-console
  console.log(`magic-link demo on http://127.0.0.1:${port}`);
});
