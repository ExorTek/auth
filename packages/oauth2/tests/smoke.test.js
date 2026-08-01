import assert from 'node:assert/strict';
import { test } from 'node:test';

import * as oauth2 from '../src/index.js';
import { ErrorCode, OAuth2Error } from '../src/index.js';

test('public surface is present', () => {
  for (const name of [
    'ErrorCode',
    'OAuth2Error',
    'CODE_CHALLENGE_METHOD',
    'createPkcePair',
    'challengeFromVerifier',
    'verifyChallenge',
    'randomState',
    'randomNonce',
  ]) {
    assert.ok(name in oauth2, `missing export: ${name}`);
  }
});

test('OAuth2Error carries a stable code and HTTP status', () => {
  const err = new OAuth2Error(ErrorCode.INVALID_ARGUMENT, 'bad');
  assert.equal(err.code, 'INVALID_ARGUMENT');
  assert.equal(err.status, 400);
  assert.equal(err.name, 'OAuth2Error');
  assert.ok(err instanceof Error);
});
