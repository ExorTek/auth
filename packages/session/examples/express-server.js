// Express session-middleware demo.
//
//   node packages/session/examples/express-server.js
//
// Then in another terminal (use -c to preserve the cookie jar):
//
//   # Login — issues a session cookie
//   curl -s -c cookies.txt -X POST http://127.0.0.1:3000/login \
//     -H 'content-type: application/json' \
//     -d '{"userId":"usr_123"}'
//
//   # Read who we are — cookie is sent back
//   curl -s -b cookies.txt http://127.0.0.1:3000/whoami
//
//   # Log out — cookie is cleared
//   curl -s -b cookies.txt -c cookies.txt -X POST http://127.0.0.1:3000/logout
//
//   # After logout — whoami says "not signed in"
//   curl -s -b cookies.txt http://127.0.0.1:3000/whoami
//
// Requires: `yarn workspace @exortek/session add express` in dev.

import express from 'express';
import { sessionMiddleware } from '../src/middleware/express.js';
import { memoryStore } from '../src/index.js';

const SECRET = 'x'.repeat(32); // demo only — read from env in prod

const app = express();
app.use(express.json());

// Development shim: memory store keeps the demo self-contained.
// In production, use `redisStore(new Redis(url))` and set
// `cookie.secure: true` with HTTPS.
const store = memoryStore();

const { middleware } = sessionMiddleware({
  secret: SECRET,
  ttl: '7d',
  idleTtl: '30m',
  store,
  cookie: {
    // __Host- prefix requires Secure + Path=/ + no Domain. Drop the
    // secure requirement for a local HTTP demo — production must set
    // both back.
    name: 'sid',
    secure: false,
    sameSite: 'lax',
  },
});

app.use(middleware);

app.post('/login', async (req, res) => {
  const { userId } = req.body ?? {};
  if (!userId) return res.status(400).json({ error: 'userId required' });
  const result = await req.sessions.issue({
    userId,
    metadata: { via: 'demo' },
  });
  res.setSessionCookie(result.cookie);
  res.json({ ok: true, sid: result.session.sid, userId });
});

app.get('/whoami', (req, res) => {
  if (!req.session) return res.json({ signedIn: false });
  res.json({
    signedIn: true,
    userId: req.session.userId,
    sid: req.session.sid,
    createdAt: req.session.createdAt,
    lastSeenAt: req.session.lastSeenAt,
  });
});

app.post('/logout', async (req, res) => {
  await res.clearSessionCookie();
  res.json({ ok: true });
});

const port = process.env.PORT ?? 3000;
app.listen(port, () => {
  // eslint-disable-next-line no-console
  console.log(`session demo on http://127.0.0.1:${port}`);
});
