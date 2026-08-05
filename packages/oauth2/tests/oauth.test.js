import assert from 'node:assert/strict';
import { test, before, after } from 'node:test';

import { createOAuth, defineProvider, ErrorCode } from '../src/index.js';
import { makeSigner, startStubAS } from './helpers/oidc.js';

const CLIENT_ID = 'client-abc';

let signer;
let as;
let idTokenToServe;

before(async () => {
  signer = await makeSigner();
  as = await startStubAS({
    publicJwks: [signer.publicJwk],
    token: () => ({ access_token: 'access-1', token_type: 'Bearer', id_token: idTokenToServe, scope: 'openid email' }),
    userinfo: () => ({ sub: 'user-1', email: 'a@b.com', email_verified: true }),
  });
});

after(() => as.close());

function testProvider(overrides = {}) {
  return defineProvider({
    id: 'test',
    kind: 'oidc',
    authorizationEndpoint: `${as.base}/authorize`,
    tokenEndpoint: `${as.base}/token`,
    userinfoEndpoint: `${as.base}/userinfo`,
    revocationEndpoint: `${as.base}/revoke`,
    jwksUri: as.jwksUri,
    issuer: as.issuer,
    defaultScopes: ['email'],
    jwksOptions: { allowInsecure: true },
    mapUser: raw => ({ sub: raw.sub, email: raw.email, emailVerified: raw.email_verified }),
    ...overrides,
  });
}

function mkOAuth(extra = {}) {
  return createOAuth({
    baseUrl: 'https://app.com',
    callback: '/auth/{provider}/callback',
    providers: [testProvider()({ clientId: CLIENT_ID, clientSecret: 'secret' })],
    ...extra,
  });
}

test('providers / has expose the registry', () => {
  const oauth = mkOAuth();
  assert.deepEqual(oauth.providers, ['test']);
  assert.equal(oauth.has('test'), true);
  assert.equal(oauth.has('nope'), false);
});

test('derives the redirect_uri from baseUrl + callback', async () => {
  const oauth = mkOAuth();
  const { url } = await oauth.authorize('test');
  assert.equal(new URL(url).searchParams.get('redirect_uri'), 'https://app.com/auth/test/callback');
});

test('stateless authorize → callback round-trip resolves the user', async () => {
  const oauth = mkOAuth();
  const { session } = await oauth.authorize('test');
  const parsed = JSON.parse(Buffer.from(session, 'base64url').toString());
  idTokenToServe = await signer.mint(
    { iss: as.issuer, sub: 'user-1', aud: CLIENT_ID, nonce: parsed.nonce },
    { expiresIn: '5m' },
  );
  const { user } = await oauth.callback('test', { code: 'c', state: parsed.state }, { session });
  assert.equal(user.sub, 'user-1');
  assert.equal(user.provider, 'test');
});

// Audit C1 — a client-held session past `maxAuthAge` must not replay.
test('a flow session older than maxAuthAge is rejected (audit C1)', async () => {
  const oauth = mkOAuth({ security: { maxAuthAge: '5m' } });
  const { session } = await oauth.authorize('test');
  const parsed = JSON.parse(Buffer.from(session, 'base64url').toString());
  // Backdate createdAt beyond the window and re-seal the client-held session.
  parsed.createdAt = Date.now() - 6 * 60 * 1000;
  const stale = Buffer.from(JSON.stringify(parsed)).toString('base64url');
  await assert.rejects(oauth.callback('test', { code: 'c', state: parsed.state }, { session: stale }), err => {
    assert.equal(err.code, ErrorCode.SESSION_EXPIRED);
    return true;
  });
});

test('store-backed round-trip looks the session up by state and is single-use', async () => {
  const map = new Map();
  const store = {
    set: (k, v) => map.set(k, v),
    get: k => map.get(k),
    delete: k => map.delete(k),
  };
  const oauth = mkOAuth({ store });

  const { session } = await oauth.authorize('test');
  const parsed = JSON.parse(Buffer.from(session, 'base64url').toString());
  assert.ok(map.has(parsed.state)); // persisted

  idTokenToServe = await signer.mint(
    { iss: as.issuer, sub: 'user-1', aud: CLIENT_ID, nonce: parsed.nonce },
    { expiresIn: '5m' },
  );
  const { user } = await oauth.callback('test', { code: 'c', state: parsed.state });
  assert.equal(user.sub, 'user-1');
  assert.ok(!map.has(parsed.state)); // consumed

  // Replay must fail — the stored session is gone.
  await assert.rejects(oauth.callback('test', { code: 'c', state: parsed.state }), err => {
    assert.equal(err.code, ErrorCode.STATE_MISMATCH);
    return true;
  });
});

// Audit C8 — a multi-tenant (function) issuer must be RUN against query.iss,
// not skipped because it is not a plain string.
test('a function-valued expectedIssuer is enforced against query.iss (audit C8)', async () => {
  const provider = defineProvider({
    id: 'fn',
    kind: 'oauth2',
    authorizationEndpoint: `${as.base}/authorize`,
    tokenEndpoint: `${as.base}/token`,
    userinfoEndpoint: `${as.base}/userinfo`,
    expectedIssuer: claimed => claimed === as.issuer,
    mapUser: raw => ({ sub: raw.sub }),
  })({ clientId: CLIENT_ID, clientSecret: 'secret' });
  const oauth = createOAuth({
    baseUrl: 'https://app.com',
    callback: '/auth/{provider}/callback',
    providers: [provider],
  });

  const { session } = await oauth.authorize('fn');
  const parsed = JSON.parse(Buffer.from(session, 'base64url').toString());

  // A forged iss the validator rejects → mismatch.
  await assert.rejects(
    oauth.callback('fn', { code: 'c', state: parsed.state, iss: 'https://evil.example' }, { session }),
    err => {
      assert.equal(err.code, ErrorCode.ISSUER_MISMATCH);
      return true;
    },
  );
  // The genuine iss passes.
  const ok = await oauth.callback('fn', { code: 'c', state: parsed.state, iss: as.issuer }, { session });
  assert.equal(ok.user.sub, 'user-1');
});

// Audit C10 — the SCOPE_NARROWED warning compares against the scopes THIS
// flow requested, carried on the session, not the provider defaults.
test('the scope-narrowed warning is measured against the requested scopes (audit C10)', async () => {
  const oauth = mkOAuth();
  const { session } = await oauth.authorize('test', { scope: ['email', 'custom_scope'] });
  const parsed = JSON.parse(Buffer.from(session, 'base64url').toString());
  idTokenToServe = await signer.mint(
    { iss: as.issuer, sub: 'user-1', aud: CLIENT_ID, nonce: parsed.nonce },
    { expiresIn: '5m' },
  );
  // The stub grants only 'openid email' — 'custom_scope' was dropped.
  const { warnings } = await oauth.callback('test', { code: 'c', state: parsed.state }, { session });
  const narrowed = warnings.find(w => w.code === 'SCOPE_NARROWED');
  assert.ok(narrowed, 'a narrowing warning is emitted');
  assert.match(narrowed.message, /custom_scope/);
});

test('revoke posts to the revocation endpoint', async () => {
  let revoked;
  const { createServer } = await import('node:http');
  const srv = createServer((req, res) => {
    if (req.url === '/revoke') {
      const chunks = [];
      req.on('data', c => chunks.push(c));
      req.on('end', () => {
        revoked = new URLSearchParams(Buffer.concat(chunks).toString());
        res.writeHead(200);
        res.end();
      });
      return;
    }
    res.writeHead(404);
    res.end();
  });
  await new Promise(r => srv.listen(0, '127.0.0.1', r));
  const port = srv.address().port;
  const oauth = createOAuth({
    baseUrl: 'https://app.com',
    callback: '/auth/{provider}/callback',
    providers: [
      testProvider({ revocationEndpoint: `http://127.0.0.1:${port}/revoke` })({
        clientId: CLIENT_ID,
        clientSecret: 'secret',
      }),
    ],
  });
  await oauth.revoke('test', 'tok-1', 'access_token');
  assert.equal(revoked.get('token'), 'tok-1');
  assert.equal(revoked.get('client_id'), CLIENT_ID);
  assert.equal(revoked.get('token_type_hint'), 'access_token');
  await new Promise(r => srv.close(r));
});

test('config guards', () => {
  const p = testProvider()({ clientId: CLIENT_ID });
  assert.throws(
    () => createOAuth({ baseUrl: 'https://a.com', callback: '/cb', providers: [] }),
    err => {
      assert.equal(err.code, ErrorCode.INVALID_ARGUMENT);
      return true;
    },
  );
  // duplicate ids collide
  assert.throws(
    () =>
      createOAuth({
        baseUrl: 'https://a.com',
        callback: '/{provider}',
        providers: [p, testProvider()({ clientId: 'x' })],
      }),
    err => {
      assert.equal(err.code, ErrorCode.INVALID_ARGUMENT);
      return true;
    },
  );
});

test('authorize on an unknown provider rejects', async () => {
  const oauth = mkOAuth();
  await assert.rejects(oauth.authorize('unknown'), err => {
    assert.equal(err.code, ErrorCode.INVALID_ARGUMENT);
    return true;
  });
});
