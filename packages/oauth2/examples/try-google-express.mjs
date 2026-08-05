/**
 * Try a REAL Google login in the browser — both web and api modes, no
 * Postman, no manual session/code carrying. One page, two buttons.
 *
 *   GOOGLE_ID=…apps.googleusercontent.com GOOGLE_SECRET=GOCSPX-… \
 *     node examples/try-google.mjs
 *   open http://localhost:5300
 *
 * In the Google Cloud console, add BOTH of these as authorized redirect
 * URIs for this OAuth client (the program prints them on boot too):
 *   http://localhost:5300/web/auth/google/callback
 *   http://localhost:5300/api/auth/google/callback
 */
import express from 'express';
import 'dotenv/config';

import { createOAuth } from '@exortek/oauth2';
import { google } from '@exortek/oauth2/providers/google';
import { oauthLogin } from '@exortek/oauth2/express';

const PORT = 5300;
const BASE = `http://localhost:${PORT}`;

const clientId = process.env.GOOGLE_ID;
const clientSecret = process.env.GOOGLE_SECRET;
if (!clientId || !clientSecret) {
  console.error('Set GOOGLE_ID and GOOGLE_SECRET env vars first.');
  process.exit(1);
}

const provider = () => google({ clientId, clientSecret });

// Two hubs so each mode gets its own callback path (and redirect_uri).
const oauthWeb = createOAuth({ baseUrl: BASE, callback: '/web/auth/{provider}/callback', providers: [provider()] });
const oauthApi = createOAuth({ baseUrl: BASE, callback: '/api/auth/{provider}/callback', providers: [provider()] });

const app = express();
app.use(express.json());

//  WEB MODE — one click, flow session in a signed cookie
const web = oauthLogin({
  oauth: oauthWeb,
  mode: 'web',
  cookie: { secret: 'dev-only-change-me' },
  onSuccess: ({ res, user }) =>
    res.send(
      page(`✅ <b>Web mode</b> — logged in as ${user.email ?? user.sub}<pre>${esc(user)}</pre><a href="/">← back</a>`),
    ),
  onError: ({ res, error }) =>
    res.status(400).send(page(`❌ ${error.code ?? error.message}<br><a href="/">← back</a>`)),
});
app.get('/web/auth/:provider', web.start);
app.get('/web/auth/:provider/callback', web.callback);

//  API MODE — client holds the session; a bridge page finishes it
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
// Google redirects (GET) here; this page reads the query + the stored
// session and POSTs them to /complete — the whole api dance, automatic.
app.get('/api/auth/:provider/callback', (_req, res) => res.send(bridgePage()));

app.get('/', (_req, res) => res.send(page(landing())));

app.listen(PORT, () => {
  console.log(`\n  ${BASE}\n`);
  console.log('  Add these to your Google OAuth client (Authorized redirect URIs):');
  console.log(`    ${BASE}/web/auth/google/callback`);
  console.log(`    ${BASE}/api/auth/google/callback\n`);
});

// HTML
function esc(o) {
  return JSON.stringify(o, null, 2).replace(/</g, '&lt;');
}
function page(body) {
  return `<!doctype html><meta charset=utf8><title>oauth2 · Google</title>
    <style>body{font:16px system-ui;max-width:42rem;margin:4rem auto;padding:0 1rem;line-height:1.5}
    button,a.btn{font:inherit;padding:.5rem 1rem;cursor:pointer;border:1px solid #888;border-radius:.4rem;
    background:#fff;text-decoration:none;color:inherit;display:inline-block}pre{background:#f4f4f4;padding:1rem;overflow:auto}</style>
    <body>${body}`;
}
function landing() {
  return `<h1>@exortek/oauth2 · Google</h1>
    <p>Two ways to log in with the same core.</p>
    <h2>Web mode</h2><p>Browser redirect, flow session in a signed cookie.</p>
    <p><a class=btn href="/web/auth/google">Log in with Google (web)</a></p>
    <h2>API mode</h2><p>Client-held session (mobile / SPA style).</p>
    <p><button onclick="apiLogin()">Log in with Google (api)</button></p>
    <pre id=out></pre>
    <script>
      async function apiLogin(){
        const r = await fetch('/api/auth/google/start',{method:'POST'}).then(r=>r.json());
        sessionStorage.setItem('flow', r.session);
        location = r.authorizeUrl;
      }
    </script>`;
}
function bridgePage() {
  return `<!doctype html><meta charset=utf8>
    <style>body{font:16px system-ui;max-width:42rem;margin:4rem auto;padding:0 1rem}pre{background:#f4f4f4;padding:1rem;overflow:auto}</style>
    <body><pre id=out>finishing…</pre><a href="/">← back</a><script>
    (async () => {
      const q = Object.fromEntries(new URLSearchParams(location.search));
      const session = sessionStorage.getItem('flow');
      const r = await fetch('/api/auth/google/complete',{method:'POST',
        headers:{'content-type':'application/json'}, body: JSON.stringify({ session, ...q })}).then(r=>r.json());
      document.getElementById('out').textContent = r.user
        ? '✅ API mode — logged in as ' + (r.user.email || r.user.sub) + '\\n' + JSON.stringify(r.user, null, 2)
        : '❌ ' + r.error;
    })();
  </script>`;
}
