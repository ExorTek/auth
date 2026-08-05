import assert from 'node:assert/strict';
import { test } from 'node:test';

import { OAuth2Error } from '../src/index.js';
import { resolveRedirectUri } from '../src/internal/redirect-uri.js';

test('substitutes {provider} and joins to the base origin', () => {
  const uri = resolveRedirectUri('https://app.com', '/auth/{provider}/callback', 'google');
  assert.equal(uri, 'https://app.com/auth/google/callback');
});

test('an explicit override wins over the template', () => {
  const uri = resolveRedirectUri('https://app.com', '/auth/{provider}/callback', 'google', 'https://app.com/cb');
  assert.equal(uri, 'https://app.com/cb');
});

test('loopback http is allowed for local development', () => {
  assert.equal(
    resolveRedirectUri('http://localhost:3000', '/auth/{provider}/callback', 'github'),
    'http://localhost:3000/auth/github/callback',
  );
  assert.equal(resolveRedirectUri('http://127.0.0.1:3000', '/cb', 'github'), 'http://127.0.0.1:3000/cb');
});

test('non-loopback http is rejected (cleartext transport)', () => {
  assert.throws(() => resolveRedirectUri('http://app.com', '/cb', 'google'), OAuth2Error);
  assert.throws(() => resolveRedirectUri('https://app.com', '/cb', 'google', 'http://evil.com/cb'), OAuth2Error);
});

test('bad config throws INVALID_ARGUMENT', () => {
  const isInvalidArg = err => err instanceof OAuth2Error && err.code === 'INVALID_ARGUMENT';
  assert.throws(() => resolveRedirectUri('', '/cb', 'google'), isInvalidArg);
  assert.throws(() => resolveRedirectUri('https://app.com', '', 'google'), isInvalidArg);
});
