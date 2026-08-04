/**
 * Live config-guard tests — a bulwark against the preset endpoints
 * silently drifting out of date. These make NO authenticated calls and
 * need NO client credentials: the authorization-code flow requires an
 * interactive browser login, so a real end-to-end run can't be
 * automated. What CAN be checked without secrets is that the endpoints
 * and issuers baked into each preset still match what the provider
 * publishes today.
 *
 * Two checks:
 *   - OIDC presets → fetch the provider's live
 *     `/.well-known/openid-configuration` and assert our hardcoded
 *     `authorization_endpoint` / `token_endpoint` / `jwks_uri` (and,
 *     where the issuer is a fixed string, `issuer`) still agree.
 *   - OAuth2-only presets → no discovery document exists, so just
 *     confirm each authorization/token host is reachable (any HTTP
 *     response, redirects included), which catches a moved domain.
 *
 * Network-dependent, so opt-in and skipped by default:
 *
 *   OAUTH2_LIVE=1 yarn workspace @exortek/oauth2 test
 *
 * A provider that is simply unreachable (network/DNS/timeout) is
 * reported and tolerated; a provider that responds with endpoints that
 * DISAGREE with our preset fails the suite.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { google } from '../src/providers/google.js';
import { microsoft } from '../src/providers/microsoft.js';
import { apple } from '../src/providers/apple.js';
import { linkedin } from '../src/providers/linkedin.js';
import { twitch } from '../src/providers/twitch.js';
import { github } from '../src/providers/github.js';
import { discord } from '../src/providers/discord.js';
import { spotify } from '../src/providers/spotify.js';
import { facebook } from '../src/providers/facebook.js';
import { twitter } from '../src/providers/twitter.js';

const skipMsg = process.env.OAUTH2_LIVE ? false : 'OAUTH2_LIVE not set — skipping live config-guard tests';
const CREDS = { clientId: 'live-config-guard' };
const TIMEOUT_MS = 10_000;

// OIDC presets whose endpoints we can verify against a published
// discovery document. The well-known URL is derived from the fixed
// string `issuer` unless a target overrides it. `checkIssuer` is off
// for the multi-tenant Microsoft endpoint, whose issuer is a validator
// function (not a literal) and whose discovery `issuer` is a
// per-directory template (`.../{tenantid}/v2.0`) rather than a literal.
const oidcTargets = [
  { name: 'google', def: google(CREDS).def, checkIssuer: true },
  { name: 'apple', def: apple(CREDS).def, checkIssuer: true },
  { name: 'linkedin', def: linkedin(CREDS).def, checkIssuer: true },
  { name: 'twitch', def: twitch(CREDS).def, checkIssuer: true },
  {
    name: 'microsoft',
    def: microsoft({ ...CREDS, tenant: 'common' }).def,
    wellKnown: 'https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration',
    checkIssuer: false,
  },
];

// OAuth2-only presets — no discovery, so we only prove the hosts exist.
const oauth2Targets = [github, discord, spotify, facebook, twitter].map(p => {
  const { def } = p(CREDS);
  return { name: def.id, authorizationEndpoint: def.authorizationEndpoint, tokenEndpoint: def.tokenEndpoint };
});

/** Fetch a URL with a timeout; return the Response (redirects unfollowed). */
async function fetchWithTimeout(url, init = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    return await fetch(url, { redirect: 'manual', signal: controller.signal, ...init });
  } finally {
    clearTimeout(timer);
  }
}

/** The host+path of a URL, dropping the query — endpoints are compared bare. */
function bare(url) {
  const u = new URL(url);
  return `${u.origin}${u.pathname}`;
}

for (const target of oidcTargets) {
  test(`${target.name}: preset endpoints match live discovery`, { skip: skipMsg }, async t => {
    const { def } = target;
    const wellKnown = target.wellKnown ?? `${String(def.issuer).replace(/\/$/, '')}/.well-known/openid-configuration`;

    let doc;
    try {
      const res = await fetchWithTimeout(wellKnown, { headers: { accept: 'application/json' } });
      if (!res.ok) {
        t.diagnostic(`${target.name}: discovery ${wellKnown} returned ${res.status} — tolerated, skipping compare`);
        return;
      }
      doc = await res.json();
    } catch (err) {
      t.diagnostic(`${target.name}: discovery unreachable (${err.message}) — tolerated, skipping compare`);
      return;
    }

    // Endpoints the preset hardcodes must equal the live document.
    // Facebook-style query params never appear on OIDC endpoints, but
    // compare bare host+path defensively.
    if (def.authorizationEndpoint) {
      assert.equal(
        bare(doc.authorization_endpoint),
        bare(def.authorizationEndpoint),
        `${target.name} authorization_endpoint drifted`,
      );
    }
    if (def.tokenEndpoint) {
      assert.equal(bare(doc.token_endpoint), bare(def.tokenEndpoint), `${target.name} token_endpoint drifted`);
    }
    if (def.jwksUri) {
      assert.equal(bare(doc.jwks_uri), bare(def.jwksUri), `${target.name} jwks_uri drifted`);
    }
    if (target.checkIssuer) {
      assert.equal(doc.issuer, def.issuer, `${target.name} issuer drifted`);
    }
  });
}

for (const target of oauth2Targets) {
  test(`${target.name}: authorization + token hosts are reachable`, { skip: skipMsg }, async t => {
    for (const url of [target.authorizationEndpoint, target.tokenEndpoint]) {
      try {
        // Any HTTP response — 200/302/400/405 — proves the host+path
        // exist. We deliberately do not follow redirects (a bare
        // authorization GET bounces to a login page) or assert a
        // status; only a transport failure means the endpoint moved.
        const res = await fetchWithTimeout(bare(url));
        t.diagnostic(`${target.name}: ${bare(url)} → ${res.status}`);
        assert.ok(res.status > 0, `${bare(url)} returned no status`);
      } catch (err) {
        assert.fail(`${target.name}: ${bare(url)} is unreachable — endpoint may have moved (${err.message})`);
      }
    }
  });
}
