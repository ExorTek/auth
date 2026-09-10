import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { ErrorCode, createProvider } from '../src/index.js';
import { computeSessionState } from '../src/internal/session.js';
import { makeSigner } from './helpers/oidc.js';

const ISSUER = 'https://auth.example.com';

async function makeProvider(session = {}) {
  const signer = await makeSigner();
  return createProvider({
    issuer: ISSUER,
    signing: { key: signer.privateJwk, alg: signer.alg, kid: signer.kid },
    jwks: [signer.publicJwk],
    endpoints: { authorization: '/authorize', token: '/token' },
    session,
  });
}

describe('computeSessionState', () => {
  it('is deterministic for the same inputs + salt and changes with browser state', () => {
    const a = computeSessionState({ clientId: 'c', origin: 'https://app', opBrowserState: 'state-1', salt: 'salty' });
    const b = computeSessionState({ clientId: 'c', origin: 'https://app', opBrowserState: 'state-1', salt: 'salty' });
    const c = computeSessionState({ clientId: 'c', origin: 'https://app', opBrowserState: 'state-2', salt: 'salty' });
    assert.equal(a, b);
    assert.notEqual(a, c);
    assert.match(a, /^[\w-]+\.salty$/);
  });

  it('generates a random salt when none is given', () => {
    const a = computeSessionState({ clientId: 'c', origin: 'https://app', opBrowserState: 's' });
    const b = computeSessionState({ clientId: 'c', origin: 'https://app', opBrowserState: 's' });
    assert.notEqual(a.split('.')[1], b.split('.')[1]);
  });
});

describe('provider session management', () => {
  it('advertises check_session_iframe once session is configured', async () => {
    const provider = await makeProvider();
    const doc = JSON.parse(provider.discoveryHandler()().body);
    assert.equal(doc.check_session_iframe, `${ISSUER}/check_session`);
  });

  it('sessionState() validates its input', async () => {
    const provider = await makeProvider();
    assert.throws(() => provider.sessionState({ clientId: 'c' }), { code: ErrorCode.INVALID_ARGUMENT });
    const ss = provider.sessionState({ clientId: 'c', origin: 'https://app', opBrowserState: 'x' });
    assert.match(ss, /\./);
  });

  it('serves an HTML check-session iframe embedding the configured cookie name', async () => {
    const provider = await makeProvider({ cookieName: 'my_op_state' });
    const res = provider.checkSessionHandler()();
    assert.equal(res.status, 200);
    assert.match(res.headers['content-type'], /text\/html/);
    assert.match(res.body, /addEventListener\('message'/);
    assert.match(res.body, /"my_op_state"/);
  });
});
