import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';

import { CODE_CHALLENGE_METHOD, challengeFromVerifier, createPkcePair, verifyChallenge } from '../src/index.js';
import { OAuth2Error } from '../src/index.js';

test('createPkcePair returns an S256 pair with a 43-char verifier', () => {
  const { codeVerifier, codeChallenge, codeChallengeMethod } = createPkcePair();
  assert.equal(codeChallengeMethod, 'S256');
  assert.equal(codeChallengeMethod, CODE_CHALLENGE_METHOD);
  // base64url(32 bytes) === 43 chars, no padding
  assert.equal(codeVerifier.length, 43);
  assert.match(codeVerifier, /^[A-Za-z0-9_-]+$/);
  assert.match(codeChallenge, /^[A-Za-z0-9_-]+$/);
});

test('challengeFromVerifier matches the RFC 7636 S256 transform', () => {
  const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
  const expected = createHash('sha256').update(verifier, 'ascii').digest('base64url');
  assert.equal(challengeFromVerifier(verifier), expected);
});

test('verifyChallenge accepts the matching verifier and rejects others', () => {
  const { codeVerifier, codeChallenge } = createPkcePair();
  assert.equal(verifyChallenge(codeVerifier, codeChallenge), true);
  assert.equal(verifyChallenge(createPkcePair().codeVerifier, codeChallenge), false);
});

test('pairs are unique across calls', () => {
  const a = createPkcePair();
  const b = createPkcePair();
  assert.notEqual(a.codeVerifier, b.codeVerifier);
  assert.notEqual(a.codeChallenge, b.codeChallenge);
});

test('challengeFromVerifier rejects a non-string verifier', () => {
  assert.throws(() => challengeFromVerifier(''), OAuth2Error);
  assert.throws(() => challengeFromVerifier(undefined), OAuth2Error);
});
