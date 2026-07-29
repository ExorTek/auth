// Passkey server demo (Fastify) — register + authenticate over HTTP.
//
//   node packages/passkey/examples/fastify-server.js
//
// Then open http://localhost:3000/ in a browser (use `localhost`, not
// 127.0.0.1 — the RP ID is "localhost" and WebAuthn matches the origin
// exactly) and click "Register a passkey", then "Sign in". The served
// page (examples/dev-page.html) is a self-contained vanilla-JS client;
// no CDN or @simplewebauthn/browser needed.
//
// `@exortek/passkey` ships no framework plugin: it is a pure server-side
// verification library, so this example wires the same
// `registration` / `authentication` calls straight into Fastify routes,
// mirroring the Express demo next to it.
//
// Requires: `yarn workspace @exortek/passkey add fastify` in dev.

import Fastify from 'fastify';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { registration, authentication, PasskeyError } from '../src/index.js';

const DEV_PAGE = readFileSync(new URL('./dev-page.html', import.meta.url));

const RP = { id: 'localhost', name: 'Passkey Demo' };
const ORIGIN = 'http://localhost:3000';
const CHALLENGE_SECRET = 'demo-secret-do-not-use-in-production-please';

// Very small in-memory "IncrStore" so we can share it with @exortek/challenge.
function memoryIncrStore() {
  const map = new Map();
  return {
    async incr(key, ttlMs) {
      const now = Date.now();
      const entry = map.get(key);
      if (!entry || entry.expiresAt <= now) {
        const fresh = { count: 1, expiresAt: now + ttlMs };
        map.set(key, fresh);
        return { count: 1, expiresAt: fresh.expiresAt };
      }
      entry.count += 1;
      return { count: entry.count, expiresAt: entry.expiresAt };
    },
  };
}
const challengeStore = memoryIncrStore();

// In-memory credential store keyed by credentialId (base64url).
const credentials = new Map();
// Fake session store keyed by session id (returned as cookie).
const sessions = new Map();

const app = Fastify({ logger: false });

function getOrCreateSession(req, reply) {
  const sid = req.headers.cookie?.match(/sid=([^;]+)/)?.[1];
  if (sid && sessions.has(sid)) return sessions.get(sid);
  const fresh = { id: randomUUID(), userId: 'demo-user' };
  sessions.set(fresh.id, fresh);
  reply.header('Set-Cookie', `sid=${fresh.id}; Path=/; HttpOnly`);
  return fresh;
}

app.get('/', async (req, reply) => reply.type('text/html').send(DEV_PAGE));

app.post('/passkey/register/begin', async (req, reply) => {
  const session = getOrCreateSession(req, reply);
  const { options, challengeToken } = await registration.begin({
    rp: RP,
    user: { id: session.userId, name: 'demo@example.com', displayName: 'Demo User' },
    challengeSecret: CHALLENGE_SECRET,
    challengeStore,
    authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
  });
  session.challengeToken = challengeToken;
  return options;
});

app.post('/passkey/register/finish', async (req, reply) => {
  const session = getOrCreateSession(req, reply);
  const result = await registration.finish({
    response: req.body,
    challengeToken: session.challengeToken,
    expectedRpId: RP.id,
    expectedOrigin: ORIGIN,
    challengeSecret: CHALLENGE_SECRET,
    challengeStore,
    expectedUserId: session.userId,
  });
  credentials.set(result.credential.id, {
    userId: session.userId,
    publicKeyCose: result.credential.publicKeyCose,
    algorithm: result.credential.algorithm,
    counter: result.credential.counter,
    transports: result.credential.transports,
    aaguid: result.aaguid,
    deviceType: result.deviceType,
  });
  delete session.challengeToken;
  return { ok: true, credentialId: result.credential.id, aaguid: result.aaguid };
});

app.post('/passkey/login/begin', async (req, reply) => {
  const session = getOrCreateSession(req, reply);
  const { options, challengeToken } = await authentication.begin({
    rpId: RP.id,
    challengeSecret: CHALLENGE_SECRET,
    challengeStore,
    userVerification: 'required',
    allowCredentials: [...credentials.entries()].map(([id, row]) => ({ id, transports: row.transports })),
  });
  session.challengeToken = challengeToken;
  return options;
});

app.post('/passkey/login/finish', async (req, reply) => {
  const session = getOrCreateSession(req, reply);
  const row = credentials.get(req.body.id);
  if (!row) {
    reply.code(404);
    return { error: 'unknown credential' };
  }
  const result = await authentication.finish({
    response: req.body,
    challengeToken: session.challengeToken,
    expectedRpId: RP.id,
    expectedOrigin: ORIGIN,
    challengeSecret: CHALLENGE_SECRET,
    challengeStore,
    credential: {
      publicKeyCose: row.publicKeyCose,
      algorithm: row.algorithm,
      counter: row.counter,
    },
  });
  row.counter = result.newCounter;
  delete session.challengeToken;
  return { ok: true, verified: true };
});

app.setErrorHandler((err, req, reply) => {
  if (err instanceof PasskeyError) {
    return reply.code(err.status).send({ error: err.code, message: err.message });
  }
  reply.code(500).send({ error: 'INTERNAL', message: err.message });
});

const port = Number(process.env.PORT ?? 3000);
await app.listen({ port, host: '127.0.0.1' });
// eslint-disable-next-line no-console
console.log(`passkey demo on http://127.0.0.1:${port}`);
