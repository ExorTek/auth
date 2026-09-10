import { test } from 'node:test';
import assert from 'node:assert/strict';

import * as auth from '../src/index.js';

// Each entry: [ root namespace binding, its upstream package specifier ].
// The umbrella must expose exactly the same bindings the leaf package does,
// pointing at the very same values — no copies, no drift.
const NAMESPACES = [
  ['crypto', '@exortek/crypto'],
  ['jwk', '@exortek/jwk'],
  ['jws', '@exortek/jws'],
  ['jwt', '@exortek/jwt'],
  ['jwe', '@exortek/jwe'],
  ['jwks', '@exortek/jwks'],
  ['opaque', '@exortek/opaque'],
  ['paseto', '@exortek/paseto'],
  ['password', '@exortek/password'],
  ['otp', '@exortek/otp'],
  ['challenge', '@exortek/challenge'],
  ['magicLink', '@exortek/magic-link'],
  ['passkey', '@exortek/passkey'],
  ['session', '@exortek/session'],
  ['security', '@exortek/security'],
  ['ua', '@exortek/ua'],
  ['apiKey', '@exortek/apikey'],
  ['oauth2', '@exortek/oauth2'],
  ['oidc', '@exortek/oidc'],
];

test('every package is re-exported as a namespace object', () => {
  for (const [binding] of NAMESPACES) {
    assert.equal(typeof auth[binding], 'object', `missing namespace: ${binding}`);
    assert.notEqual(auth[binding], null, `null namespace: ${binding}`);
  }
});

test('the root exposes only the expected bindings', () => {
  assert.deepEqual(Object.keys(auth).sort(), NAMESPACES.map(([b]) => b).sort());
});

test('each namespace mirrors its leaf package exactly (same bindings, same values)', async () => {
  for (const [binding, specifier] of NAMESPACES) {
    const upstream = await import(specifier);
    const ns = auth[binding];
    const upstreamKeys = Object.keys(upstream)
      .filter(k => k !== 'default')
      .sort();
    assert.deepEqual(Object.keys(ns).sort(), upstreamKeys, `binding drift: ${binding}`);
    for (const key of upstreamKeys) {
      assert.equal(ns[key], upstream[key], `value drift: ${binding}.${key}`);
    }
  }
});

test('subpath shims forward the same values as the upstream subpath', async () => {
  const cases = [
    ['../src/jwt/token-pair.js', '@exortek/jwt/token-pair'],
    ['../src/oauth2/providers/google.js', '@exortek/oauth2/providers/google'],
    ['../src/crypto/hash.js', '@exortek/crypto/hash'],
    ['../src/security/fastify.js', '@exortek/security/fastify'],
    ['../src/session/stores/redis.js', '@exortek/session/stores/redis'],
    ['../src/ua/middleware/bot-guard.js', '@exortek/ua/middleware/bot-guard'],
  ];
  for (const [shim, specifier] of cases) {
    const local = await import(shim);
    const upstream = await import(specifier);
    const keys = Object.keys(upstream)
      .filter(k => k !== 'default')
      .sort();
    assert.deepEqual(
      Object.keys(local)
        .filter(k => k !== 'default')
        .sort(),
      keys,
      `subpath drift: ${specifier}`,
    );
    for (const key of keys) {
      assert.equal(local[key], upstream[key], `subpath value drift: ${specifier}.${key}`);
    }
  }
});
