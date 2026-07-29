// Passkey server demo — register + authenticate over HTTP.
//
//   node packages/passkey/examples/express-server.js
//
// Then open http://localhost:3000/ in a browser (use `localhost`, not
// 127.0.0.1 — the RP ID is "localhost" and WebAuthn matches the origin
// exactly) and click "Register a passkey", then "Sign in". The served
// page (examples/dev-page.html) is a self-contained vanilla-JS client;
// no CDN or @simplewebauthn/browser needed. The server is @exortek/passkey.
//
// Requires: `yarn workspace @exortek/passkey add express` in dev.

import express from 'express';
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

const app = express();
app.use(express.json());

app.get('/', (req, res) => res.type('html').send(DEV_PAGE));

function getOrCreateSession(req, res) {
  const sid = req.headers.cookie?.match(/sid=([^;]+)/)?.[1];
  if (sid && sessions.has(sid)) return sessions.get(sid);
  const fresh = { id: randomUUID(), userId: 'demo-user' };
  sessions.set(fresh.id, fresh);
  res.setHeader('Set-Cookie', `sid=${fresh.id}; Path=/; HttpOnly`);
  return fresh;
}

app.post('/passkey/register/begin', async (req, res, next) => {
  try {
    const session = getOrCreateSession(req, res);
    const { options, challengeToken } = await registration.begin({
      rp: RP,
      user: { id: session.userId, name: 'demo@example.com', displayName: 'Demo User' },
      challengeSecret: CHALLENGE_SECRET,
      challengeStore,
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
    });
    session.challengeToken = challengeToken;
    res.json(options);
  } catch (err) {
    next(err);
  }
});

app.post('/passkey/register/finish', async (req, res, next) => {
  try {
    const session = getOrCreateSession(req, res);
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
      aaguid: result.aaguid,
      deviceType: result.deviceType,
    });
    delete session.challengeToken;
    res.json({ ok: true, credentialId: result.credential.id, aaguid: result.aaguid });
  } catch (err) {
    next(err);
  }
});

app.post('/passkey/login/begin', async (req, res, next) => {
  try {
    const session = getOrCreateSession(req, res);
    const { options, challengeToken } = await authentication.begin({
      rpId: RP.id,
      challengeSecret: CHALLENGE_SECRET,
      challengeStore,
      userVerification: 'required',
      allowCredentials: [...credentials.entries()].map(([id, row]) => ({ id, transports: row.transports })),
    });
    session.challengeToken = challengeToken;
    res.json(options);
  } catch (err) {
    next(err);
  }
});

app.post('/passkey/login/finish', async (req, res, next) => {
  try {
    const session = getOrCreateSession(req, res);
    const row = credentials.get(req.body.id);
    if (!row) {
      return res.status(404).json({ error: 'unknown credential' });
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
    res.json({ ok: true, verified: true });
  } catch (err) {
    next(err);
  }
});

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (err instanceof PasskeyError) {
    return res.status(err.status).json({ error: err.code, message: err.message });
  }
  throw err;
});

const port = Number(process.env.PORT ?? 3000);
app.listen(port, () => console.log(`passkey demo on http://127.0.0.1:${port}`));
