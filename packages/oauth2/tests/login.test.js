import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  normalizeLoginConfig,
  startLogin,
  completeLogin,
  signValue,
  unsignValue,
  sealValue,
  unsealValue,
} from '../src/middleware/core.js';
import { mountOAuthLogin } from '../src/middleware/express.js';

const SECRET = 'flow-cookie-secret-value';

/** A hermetic stand-in for a `createOAuth` hub. */
function fakeOauth() {
  return {
    authorize: async (provider, options) => ({
      url: `https://provider.example/authorize?provider=${provider}`,
      session: JSON.stringify({ state: 'st', codeVerifier: 'v', nonce: 'n', scope: options.scope }),
      warnings: [],
    }),
    callback: async (provider, query, options) => ({
      tokens: { access_token: 'AT', refresh_token: 'RT' },
      user: { sub: 'user-1', email: 'a@b.com' },
      warnings: [],
      _sessionSeen: options.session,
      _query: query,
    }),
  };
}

test('signValue / unsignValue round-trips and rejects tampering', () => {
  const signed = signValue('payload-abc', SECRET);
  assert.equal(unsignValue(signed, SECRET), 'payload-abc');
  assert.equal(unsignValue(signed.slice(0, -1) + 'X', SECRET), undefined);
  assert.equal(unsignValue('no-signature', SECRET), undefined);
  assert.equal(unsignValue(signed, 'wrong-secret'), undefined);
});

test('web mode: signed cookie carries the flow session', async () => {
  const cfg = normalizeLoginConfig({ oauth: fakeOauth(), cookie: { secret: SECRET } });
  assert.equal(cfg.mode, 'web');
  assert.equal(cfg.cookieMode, true);

  const started = await startLogin(cfg, 'google', {});
  assert.match(started.authorizeUrl, /provider=google/);
  assert.ok(started.setCookie);
  assert.ok(started.setCookie.value.includes('.'), 'cookie value is signed');
  assert.equal(started.setCookie.options.httpOnly, true);

  const done = await completeLogin(cfg, 'google', { state: 'st', code: 'C' }, { cookieValue: started.setCookie.value });
  assert.equal(done.result.user.sub, 'user-1');
  assert.equal(done.result.provider, 'google');
  assert.equal(done.clearCookie, cfg.cookieName);
});

test('web mode: a tampered cookie is rejected', async () => {
  const cfg = normalizeLoginConfig({ oauth: fakeOauth(), cookie: { secret: SECRET } });
  const started = await startLogin(cfg, 'google', {});
  await assert.rejects(
    () => completeLogin(cfg, 'google', { state: 'st' }, { cookieValue: started.setCookie.value.slice(0, -2) + 'zz' }),
    /tampered|session/i,
  );
});

test("seal: 'jwe' encrypts the flow session (confidential, not just signed)", async () => {
  const secret = 'jwe-seal-secret-derives-a256gcm!';
  const sealed = await sealValue('flow-session-payload', secret);
  assert.equal(sealed.split('.').length, 5, 'compact JWE has five parts');
  assert.ok(!sealed.includes('flow-session-payload'), 'plaintext is not visible');
  assert.equal(await unsealValue(sealed, secret), 'flow-session-payload');
  assert.equal(await unsealValue(sealed, 'a-different-wrong-secret-value!!'), undefined);

  const cfg = normalizeLoginConfig({ oauth: fakeOauth(), cookie: { secret }, seal: 'jwe' });
  const started = await startLogin(cfg, 'google', {});
  assert.ok(!started.setCookie.value.includes('"state"'), 'the cookie ciphertext hides the session');
  const done = await completeLogin(cfg, 'google', { state: 'st', code: 'C' }, { cookieValue: started.setCookie.value });
  assert.equal(done.result.user.sub, 'user-1');
});

test("seal: 'jwe' requires a secret", () => {
  assert.throws(() => normalizeLoginConfig({ oauth: fakeOauth(), mode: 'api', seal: 'jwe' }), /secret/i);
});

test('api mode: session is client-held, no cookie', async () => {
  const cfg = normalizeLoginConfig({ oauth: fakeOauth(), mode: 'api', secret: SECRET });
  assert.equal(cfg.mode, 'api');
  assert.equal(cfg.cookieMode, false);

  const started = await startLogin(cfg, 'github', {});
  assert.ok(started.authorizeUrl);
  assert.ok(started.session, 'session returned to the client');
  assert.equal(started.setCookie, null);

  const done = await completeLogin(cfg, 'github', { state: 'st', code: 'C' }, { session: started.session });
  assert.equal(done.result.user.sub, 'user-1');
  assert.equal(done.clearCookie, null);
});

test('api mode: a missing session is a hard failure', async () => {
  const cfg = normalizeLoginConfig({ oauth: fakeOauth(), mode: 'api', secret: SECRET });
  await assert.rejects(() => completeLogin(cfg, 'github', { state: 'st' }, {}), /no flow session|session/i);
});

test('store mode (no secret): callback carries no session, relies on the store', async () => {
  const oauth = fakeOauth();
  const cfg = normalizeLoginConfig({ oauth });
  assert.equal(cfg.cookieMode, false);
  assert.equal(cfg.signed, false);

  const started = await startLogin(cfg, 'google', {});
  assert.equal(started.setCookie, null);

  // No cookie / no session — createOAuth's store looks it up by state.
  const done = await completeLogin(cfg, 'google', { state: 'st', code: 'C' }, {});
  assert.equal(done.result._sessionSeen, undefined);
  assert.equal(done.result.user.sub, 'user-1');
});

test('routes are taken verbatim; callbackPath is not constructed', async () => {
  const cfg = normalizeLoginConfig({
    oauth: fakeOauth(),
    loginPath: '/oauth/:provider/login',
    callbackPath: '/oauth/:provider/return',
    cookie: { secret: SECRET },
  });
  assert.equal(cfg.loginPath, '/oauth/:provider/login');
  assert.equal(cfg.callbackPath, '/oauth/:provider/return');
});

test('express adapter registers the mode-appropriate routes', () => {
  const registered = [];
  const app = {
    get: (path, ...h) => registered.push(['GET', path]),
    post: (path, ...h) => registered.push(['POST', path]),
  };
  mountOAuthLogin(app, { oauth: fakeOauth(), cookie: { secret: SECRET } });
  assert.deepEqual(new Set(registered.map(r => r[0])), new Set(['GET']));
  assert.ok(registered.some(r => r[1] === '/auth/:provider/callback'));
  assert.ok(registered.some(r => r[1] === '/auth/:provider'));

  const apiRegistered = [];
  const apiApp = {
    get: path => apiRegistered.push(['GET', path]),
    post: path => apiRegistered.push(['POST', path]),
  };
  mountOAuthLogin(apiApp, { oauth: fakeOauth(), mode: 'api', secret: SECRET });
  assert.deepEqual(new Set(apiRegistered.map(r => r[0])), new Set(['POST']));
});

test('express web callback runs end-to-end over mock req/res', async () => {
  const oauth = fakeOauth();
  let onSuccessArg;
  const routes = {};
  const app = { get: (p, h) => (routes[p] = h), post: (p, h) => (routes[p] = h) };
  mountOAuthLogin(app, {
    oauth,
    cookie: { secret: SECRET },
    onSuccess: ctx => (onSuccessArg = ctx),
  });

  // Start → capture the Set-Cookie the browser would send back.
  let cookieHeader;
  const startRes = {
    setHeader: (n, v) => (cookieHeader = v),
    redirect: () => {},
  };
  await routes['/auth/:provider']({ params: { provider: 'google' } }, startRes, () => {});
  assert.ok(cookieHeader, 'a flow cookie was set');
  const cookieValue = String(cookieHeader).split(';')[0].split('=').slice(1).join('=');

  // Callback → the signed cookie comes back, onSuccess receives the user.
  const cbRes = { setHeader: () => {}, redirect: () => {} };
  await routes['/auth/:provider/callback'](
    {
      params: { provider: 'google' },
      headers: { cookie: `oauth_flow=${cookieValue}` },
      query: { state: 'st', code: 'C' },
    },
    cbRes,
    () => {},
  );
  assert.equal(onSuccessArg.user.sub, 'user-1');
  assert.equal(onSuccessArg.provider, 'google');
});
