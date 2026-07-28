import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { base64url } from '@exortek/crypto/encode';
import { parseClientData } from '../../src/webauthn/clientData.js';

function encodeJson(obj) {
  return new TextEncoder().encode(JSON.stringify(obj));
}

describe('clientData — parseClientData', () => {
  test('parses a minimal webauthn.create payload', () => {
    const challengeBytes = new Uint8Array([1, 2, 3, 4, 5]);
    const bytes = encodeJson({
      type: 'webauthn.create',
      challenge: base64url.encode(challengeBytes),
      origin: 'https://example.com',
    });
    const out = parseClientData(bytes);
    assert.equal(out.type, 'webauthn.create');
    assert.deepEqual(out.challenge, challengeBytes);
    assert.equal(out.origin, 'https://example.com');
    assert.equal(out.crossOrigin, false);
    assert.deepEqual(out.raw, bytes);
  });

  test('parses webauthn.get with crossOrigin=true', () => {
    const bytes = encodeJson({
      type: 'webauthn.get',
      challenge: base64url.encode(new Uint8Array([9])),
      origin: 'https://example.com',
      crossOrigin: true,
    });
    const out = parseClientData(bytes);
    assert.equal(out.type, 'webauthn.get');
    assert.equal(out.crossOrigin, true);
  });

  test('rejects non-Uint8Array', () => {
    assert.throws(() => parseClientData('{"type":"webauthn.get"}'), /Uint8Array/);
  });

  test('rejects invalid UTF-8', () => {
    assert.throws(() => parseClientData(new Uint8Array([0xff, 0xfe])), /UTF-8/);
  });

  test('rejects invalid JSON', () => {
    assert.throws(() => parseClientData(new TextEncoder().encode('not json')), /valid JSON/);
  });

  test('rejects JSON array root', () => {
    assert.throws(() => parseClientData(new TextEncoder().encode('[]')), /root must be a JSON object/);
  });

  test('rejects unknown type', () => {
    const bytes = encodeJson({
      type: 'webauthn.other',
      challenge: 'a',
      origin: 'https://x',
    });
    assert.throws(() => parseClientData(bytes), /is not "webauthn.create" or "webauthn.get"/);
  });

  test('rejects missing challenge', () => {
    const bytes = encodeJson({ type: 'webauthn.create', origin: 'https://x' });
    assert.throws(() => parseClientData(bytes), /challenge missing/);
  });

  test('rejects missing origin', () => {
    const bytes = encodeJson({ type: 'webauthn.create', challenge: 'a' });
    assert.throws(() => parseClientData(bytes), /origin missing/);
  });

  test('rejects crossOrigin non-boolean', () => {
    const bytes = encodeJson({
      type: 'webauthn.create',
      challenge: 'a',
      origin: 'https://x',
      crossOrigin: 'yes',
    });
    assert.throws(() => parseClientData(bytes), /crossOrigin must be a boolean/);
  });

  test('rejects zero-byte challenge after decode', () => {
    // Empty base64url decodes to zero bytes.
    const bytes = encodeJson({
      type: 'webauthn.create',
      challenge: '',
      origin: 'https://x',
    });
    assert.throws(() => parseClientData(bytes), /challenge missing/);
  });
});
