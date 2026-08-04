import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { test } from 'node:test';

import { createOAuth, defineProvider } from '../src/index.js';
import { buildAuthorization, handleCallback } from '../src/providers/_base.js';
import { google } from '../src/providers/google.js';
import { github } from '../src/providers/github.js';
import { microsoft } from '../src/providers/microsoft.js';
import { discord } from '../src/providers/discord.js';
import { facebook } from '../src/providers/facebook.js';
import { linkedin } from '../src/providers/linkedin.js';
import { spotify } from '../src/providers/spotify.js';
import { twitch } from '../src/providers/twitch.js';
import { apple } from '../src/providers/apple.js';
import { twitter } from '../src/providers/twitter.js';
import { okta } from '../src/providers/okta.js';
import { azure } from '../src/providers/azure.js';

const CREDS = { clientId: 'id', clientSecret: 'secret' };

test('every preset builds a provider descriptor', () => {
  const built = [
    google(CREDS),
    github(CREDS),
    microsoft(CREDS),
    discord(CREDS),
    facebook(CREDS),
    linkedin(CREDS),
    spotify(CREDS),
    twitch(CREDS),
    apple(CREDS),
    twitter(CREDS),
    okta({ ...CREDS, issuer: 'https://org.okta.com/oauth2/default' }),
    azure(CREDS),
  ];
  assert.equal(built.length, 12);
  for (const p of built) {
    assert.equal(p.__oauth2Provider, true);
    assert.ok(p.id);
    assert.ok(p.kind === 'oidc' || p.kind === 'oauth2');
  }
});

test('OIDC vs OAuth2 kinds are correct', () => {
  const oidc = { google, microsoft, linkedin, twitch, apple };
  const oauth2 = { github, discord, facebook, spotify, twitter };
  for (const [, p] of Object.entries(oidc)) {
    assert.equal(p(CREDS).kind, 'oidc');
  }
  for (const [, p] of Object.entries(oauth2)) {
    assert.equal(p(CREDS).kind, 'oauth2');
  }
});

test('okta requires an issuer', () => {
  assert.throws(() => okta(CREDS), /issuer/);
});

test('microsoft pins the issuer for a concrete tenant and validates for common', () => {
  const single = microsoft({ ...CREDS, tenant: '11111111-1111-1111-1111-111111111111' });
  assert.equal(single.def.issuer, 'https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0');
  assert.match(single.def.authorizationEndpoint, /11111111-1111-1111-1111-111111111111/);

  const common = microsoft(CREDS);
  assert.equal(typeof common.def.issuer, 'function');
  assert.equal(common.def.issuer('https://login.microsoftonline.com/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/v2.0'), true);
  assert.equal(common.def.issuer('https://evil.example/v2.0'), false);
});

test('mapUser normalizes representative payloads', () => {
  assert.deepEqual(
    google(CREDS).def.mapUser({ sub: 'g1', email: 'g@x.com', email_verified: true, name: 'G', picture: 'p' }),
    { sub: 'g1', email: 'g@x.com', emailVerified: true, name: 'G', picture: 'p' },
  );

  // github: id → sub, primary verified email from the emails array.
  assert.deepEqual(
    github(CREDS).def.mapUser({
      id: 42,
      login: 'octo',
      name: 'The Octo',
      avatar_url: 'http://a',
      emails: [
        { email: 'secondary@x.com', primary: false, verified: true },
        { email: 'primary@x.com', primary: true, verified: true },
      ],
    }),
    { sub: '42', email: 'primary@x.com', emailVerified: true, name: 'The Octo', picture: 'http://a' },
  );

  // discord: avatar hash → CDN url, global_name preferred.
  const d = discord(CREDS).def.mapUser({
    id: '9',
    username: 'u',
    global_name: 'G',
    email: 'd@x.com',
    verified: true,
    avatar: 'abc',
  });
  assert.equal(d.sub, '9');
  assert.equal(d.name, 'G');
  assert.equal(d.picture, 'https://cdn.discordapp.com/avatars/9/abc.png');

  // twitter: nested under data, no email.
  const t = twitter(CREDS).def.mapUser({ data: { id: '7', name: 'T', username: 'th', profile_image_url: 'http://i' } });
  assert.deepEqual(t, { sub: '7', name: 'T', picture: 'http://i' });

  // apple: from id_token claims, string 'true' coerced.
  const a = apple(CREDS).def.mapUser({}, { sub: 'a1', email: 'a@x.com', email_verified: 'true' });
  assert.deepEqual(a, { sub: 'a1', email: 'a@x.com', emailVerified: true });
});

test('authorize URLs carry the right scopes and params', async () => {
  const oauth = createOAuth({
    baseUrl: 'https://app.com',
    callback: '/auth/{provider}/callback',
    providers: [google(CREDS), apple(CREDS), twitter(CREDS)],
  });

  const g = new URL((await oauth.authorize('google')).url).searchParams;
  assert.deepEqual(g.get('scope').split(' '), ['openid', 'email', 'profile']);
  assert.equal(g.get('access_type'), 'offline');
  assert.ok(g.get('code_challenge'));

  // apple: openid NOT injected, form_post requested.
  const a = new URL((await oauth.authorize('apple')).url).searchParams;
  assert.deepEqual(a.get('scope').split(' '), ['name', 'email']);
  assert.equal(a.get('response_mode'), 'form_post');

  // twitter: offline.access requested, oauth2 kind → no nonce.
  const t = new URL((await oauth.authorize('twitter')).url).searchParams;
  assert.ok(t.get('scope').split(' ').includes('offline.access'));
  assert.equal(t.get('nonce'), null);
});

test('OAuth2 provider with a secondary email endpoint (github shape) resolves end-to-end', async () => {
  const srv = createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    const json = body => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(body));
    };
    if (u.pathname === '/token') {
      return json({ access_token: 'gho_1', token_type: 'bearer', scope: 'read:user user:email' });
    }
    if (u.pathname === '/user') {
      return json({ id: 5, login: 'octo', name: 'Octo', avatar_url: 'http://a' });
    }
    if (u.pathname === '/user/emails') {
      return json([{ email: 'octo@x.com', primary: true, verified: true }]);
    }
    res.writeHead(404);
    res.end();
  });
  await new Promise(r => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;

  const provider = defineProvider({
    id: 'gh',
    kind: 'oauth2',
    authorizationEndpoint: `${base}/authorize`,
    tokenEndpoint: `${base}/token`,
    userinfoEndpoint: `${base}/user`,
    emailEndpoint: `${base}/user/emails`,
    defaultScopes: ['read:user', 'user:email'],
    mapUser: raw => {
      const primary = (raw.emails ?? []).find(e => e.primary);
      return { sub: String(raw.id), email: primary?.email, emailVerified: primary?.verified, name: raw.name };
    },
  })(CREDS);

  try {
    const redirectUri = 'https://app.com/cb';
    const { session } = await buildAuthorization(provider, { redirectUri });
    const { user, warnings } = await handleCallback(provider, {
      redirectUri,
      query: { code: 'c', state: session.state },
      session,
    });
    assert.equal(user.sub, '5');
    assert.equal(user.email, 'octo@x.com');
    assert.equal(user.emailVerified, true);
    assert.deepEqual(warnings, []);
  } finally {
    await new Promise(r => srv.close(r));
  }
});
