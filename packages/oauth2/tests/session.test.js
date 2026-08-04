import assert from 'node:assert/strict';
import { test } from 'node:test';

import { ErrorCode, OAuth2Error } from '../src/index.js';
import { serializeSession, deserializeSession } from '../src/internal/session.js';

test('round-trips a flow session', () => {
  const session = {
    provider: 'google',
    state: 'abc',
    codeVerifier: 'v',
    nonce: 'n',
    createdAt: 123,
  };
  const restored = deserializeSession(serializeSession(session));
  assert.deepEqual(restored, session);
});

test('rejects a missing session', () => {
  assert.throws(
    () => deserializeSession(''),
    err => {
      assert.ok(err instanceof OAuth2Error);
      assert.equal(err.code, ErrorCode.MISSING_STATE);
      return true;
    },
  );
});

test('rejects a tampered / non-JSON session', () => {
  assert.throws(
    () => deserializeSession('!!!not-base64url-json!!!'),
    err => {
      assert.equal(err.code, ErrorCode.MISSING_STATE);
      return true;
    },
  );
});

test('rejects a session without state/provider binding', () => {
  const bad = serializeSession(/** @type {any} */ ({ createdAt: 1 }));
  assert.throws(
    () => deserializeSession(bad),
    err => {
      assert.equal(err.code, ErrorCode.MISSING_STATE);
      return true;
    },
  );
});
