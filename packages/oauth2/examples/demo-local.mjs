/**
 * Self-contained, browser-clickable demo — NO external provider or
 * credentials. One process stands up:
 *
 *   • a stub OIDC provider on :4000 (auto-consents, signs a real id_token),
 *   • a relying-party app on :3000 using @exortek/oauth2 in BOTH modes.
 *
 *   node examples/demo-local.mjs
 *   open http://localhost:3000
 *
 * From the browser:
 *   • "Web mode"  → GET redirect flow, flow session in a signed cookie.
 *   • "API mode"  → client-held session (mobile / SPA style), via a small
 *                    bridge page that keeps the session in sessionStorage.
 *
 * (Requires `express` and the built package; run from the monorepo after
 * `yarn workspace @exortek/oauth2 build`, or swap imports to `../src/…`.)
 */
import { createServer } from 'node:http';
import express from 'express';

import { generate } from '@exortek/jwk/generate';
import { sign as signJwt } from '@exortek/jwt';
import { createOAuth, defineProvider } from '@exortek/oauth2';
import { oauthLogin } from '@exortek/oauth2/express';

const RP = 'http://localhost:5300';
const IDP = 'http://localhost:5400';
const CLIENT_ID = 'demo-client';

// ── Stub OIDC provider (:4000) ────────────────────────────────────────
const { publicJwk, privateJwk } = await generate('EC', { curve: 'P-256', kid: 'demo', alg: 'ES256', use: 'sig' });
const pending = new Map(); // code → { nonce, aud, redirectUri }

createServer((req, res) => {
  const url = new URL(req.url, IDP);
  const json = (s, b) => (res.writeHead(s, { 'content-type': 'application/json' }), res.end(JSON.stringify(b)));

  if (url.pathname === '/.well-known/jwks.json') return json(200, { keys: [publicJwk] });

  // Authorization endpoint — a real provider shows a login + consent
  // screen here; the stub auto-approves a fixed user and redirects back.
  if (url.pathname === '/authorize') {
    const q = url.searchParams;
    const code = `code_${Math.random().toString(36).slice(2)}`;
    pending.set(code, { nonce: q.get('nonce'), aud: q.get('client_id'), redirectUri: q.get('redirect_uri') });
    const back = new URL(q.get('redirect_uri'));
    back.searchParams.set('code', code);
    back.searchParams.set('state', q.get('state'));
    back.searchParams.set('iss', IDP); // RFC 9207
    res.writeHead(302, { location: back.href });
    return res.end();
  }

  // Token endpoint — exchange the code for an id_token + access token.
  if (url.pathname === '/token' && req.method === 'POST') {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', async () => {
      const body = new URLSearchParams(Buffer.concat(chunks).toString());
      const ctx = pending.get(body.get('code')) ?? {};
      pending.delete(body.get('code'));
      const idToken = await signJwt(
        {
          iss: IDP,
          sub: 'user-42',
          aud: ctx.aud ?? CLIENT_ID,
          nonce: ctx.nonce ?? undefined,
          email: 'demo@example.com',
        },
        privateJwk,
        { alg: 'ES256', kid: 'demo', expiresIn: '5m' },
      );
      json(200, { access_token: 'demo-access', token_type: 'Bearer', id_token: idToken, scope: 'openid email' });
    });
    return;
  }

  if (url.pathname === '/userinfo') return json(200, { sub: 'user-42', email: 'demo@example.com' });
  json(404, { error: 'not_found' });
}).listen(5400, () => console.log(`stub IdP  → ${IDP}`));

// ── Relying party (:3000) ─────────────────────────────────────────────
const localProvider = () =>
  defineProvider({
    id: 'local',
    kind: 'oidc',
    authorizationEndpoint: `${IDP}/authorize`,
    tokenEndpoint: `${IDP}/token`,
    userinfoEndpoint: `${IDP}/userinfo`,
    jwksUri: `${IDP}/.well-known/jwks.json`,
    issuer: IDP,
    defaultScopes: ['openid', 'email'],
    jwksOptions: { allowInsecure: true }, // http jwks — demo only
    mapUser: raw => ({ sub: raw.sub, email: raw.email }),
  })({ clientId: CLIENT_ID, clientSecret: 'demo-secret' });

const oauthWeb = createOAuth({ baseUrl: RP, callback: '/web/auth/{provider}/callback', providers: [localProvider()] });
const oauthApi = createOAuth({ baseUrl: RP, callback: '/api/auth/{provider}/callback', providers: [localProvider()] });

const app = express();
app.use(express.json());

// WEB MODE — one click, flow session in a signed cookie.
const web = oauthLogin({
  oauth: oauthWeb,
  mode: 'web',
  cookie: { secret: 'demo-only-secret' },
  onSuccess: ({ res, user }) => res.send(page(`✅ Web mode — logged in as <b>${user.email}</b> (sub ${user.sub})`)),
  onError: ({ res, error }) => res.status(400).send(page(`❌ ${error.code ?? error.message}`)),
});
app.get('/web/auth/:provider', web.start);
app.get('/web/auth/:provider/callback', web.callback);

// API MODE — client holds the session; a bridge page does the dance.
app.post('/api/auth/:provider/start', async (req, res) => {
  const { url, session } = await oauthApi.authorize(req.params.provider);
  res.json({ authorizeUrl: url, session });
});
app.post('/api/auth/:provider/complete', async (req, res) => {
  try {
    const { session, ...query } = req.body;
    const { user } = await oauthApi.callback(req.params.provider, query, { session });
    res.json({ user });
  } catch (err) {
    res.status(400).json({ error: err.code ?? String(err) });
  }
});
// The provider redirects (GET) here; this page finishes the api flow in JS.
app.get('/api/auth/:provider/callback', (_req, res) => res.send(bridgePage()));

app.get('/', (_req, res) => res.send(page(landing())));
app.listen(5300, () => console.log(`RP app    → ${RP}\n\nopen ${RP}`));

// ── HTML helpers ──────────────────────────────────────────────────────
function page(body) {
  return `<!doctype html><meta charset=utf8><title>oauth2 demo</title>
    <style>body{font:16px system-ui;max-width:40rem;margin:4rem auto;padding:0 1rem}a,button{font:inherit}
    button{padding:.5rem 1rem;cursor:pointer}</style><body>${body}`;
}
function landing() {
  return `<h1>@exortek/oauth2 — local demo</h1>
    <p>No real provider — a stub IdP on :4000 stands in for Google.</p>
    <h2>Web mode</h2><p><a href="/web/auth/local">→ Log in (redirect + cookie)</a></p>
    <h2>API mode</h2><p><button onclick="apiLogin()">→ Log in (client-held session)</button></p>
    <pre id=out></pre>
    <script>
      async function apiLogin(){
        const r = await fetch('/api/auth/local/start',{method:'POST'}).then(r=>r.json());
        sessionStorage.setItem('flow', r.session);
        location = r.authorizeUrl;
      }
    </script>`;
}
function bridgePage() {
  return `<!doctype html><meta charset=utf8><body><pre id=out>finishing…</pre><script>
    (async () => {
      const q = Object.fromEntries(new URLSearchParams(location.search));
      const session = sessionStorage.getItem('flow');
      const r = await fetch('/api/auth/local/complete',{method:'POST',
        headers:{'content-type':'application/json'},
        body: JSON.stringify({ session, ...q })}).then(r=>r.json());
      document.getElementById('out').textContent =
        r.user ? '✅ API mode — logged in as ' + r.user.email + ' (sub ' + r.user.sub + ')' : '❌ ' + r.error;
    })();
  </script>`;
}
