// Fastify session-plugin demo.
//
//   node packages/session/examples/fastify-server.js
//
// Then in another terminal:
//
//   curl -s -c cookies.txt -X POST http://127.0.0.1:3000/login \
//     -H 'content-type: application/json' \
//     -d '{"userId":"usr_123"}'
//   curl -s -b cookies.txt http://127.0.0.1:3000/whoami
//   curl -s -b cookies.txt -c cookies.txt -X POST http://127.0.0.1:3000/logout
//   curl -s -b cookies.txt http://127.0.0.1:3000/whoami
//
// Requires: `yarn workspace @exortek/session add fastify` in dev.

import Fastify from 'fastify';
import { sessionPlugin } from '../src/middleware/fastify.js';
import { memoryStore } from '../src/index.js';

const SECRET = 'x'.repeat(32); // demo only

const app = Fastify({ logger: false });

const store = memoryStore();

const { plugin } = sessionPlugin({
  secret: SECRET,
  ttl: '7d',
  idleTtl: '30m',
  store,
  cookie: {
    name: 'sid',
    secure: false,
    sameSite: 'lax',
  },
});
await app.register(plugin);

app.post('/login', async (req, reply) => {
  const { userId } = req.body ?? {};
  if (!userId) {
    reply.code(400);
    return { error: 'userId required' };
  }
  const result = await req.sessions.issue({
    userId,
    metadata: { via: 'demo' },
  });
  reply.setSessionCookie(result.cookie);
  return { ok: true, sid: result.session.sid, userId };
});

app.get('/whoami', async req => {
  if (!req.session) return { signedIn: false };
  return {
    signedIn: true,
    userId: req.session.userId,
    sid: req.session.sid,
    createdAt: req.session.createdAt,
    lastSeenAt: req.session.lastSeenAt,
  };
});

app.post('/logout', async (req, reply) => {
  await reply.clearSessionCookie();
  return { ok: true };
});

const port = Number(process.env.PORT ?? 3000);
await app.listen({ port, host: '127.0.0.1' });
// eslint-disable-next-line no-console
console.log(`session demo on http://127.0.0.1:${port}`);
