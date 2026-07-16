import { test } from 'node:test';
import assert from 'node:assert/strict';

import { thumbprint, thumbprintURI } from '../src/index.js';
import { canonicalise, REQUIRED_MEMBERS } from '../src/internal/canonical.js';

/**
 * RFC 7638 §3.1 — the reference example.
 *
 * The specification pins the following JWK to a specific SHA-256
 * thumbprint. Any implementation that produces a different digest is
 * non-conforming, which is why we hard-code the exact expected value.
 */
const RFC7638_JWK = Object.freeze({
  kty: 'RSA',
  n: '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
  e: 'AQAB',
  alg: 'RS256',
  kid: '2011-04-29',
});

/** Expected SHA-256 thumbprint, base64url encoded, from RFC 7638 §3.1. */
const RFC7638_THUMBPRINT_SHA256 = 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs';

test('RFC 7638 §3.1: canonical byte string matches the spec exactly', () => {
  const bytes = canonicalise(RFC7638_JWK);
  // The spec fixes the canonical form; changing member order or including
  // decorators like `alg` / `kid` would break this. Reconstructing it
  // literally guards against regressions in the projection code.
  const expected = `{"e":"${RFC7638_JWK.e}","kty":"${RFC7638_JWK.kty}","n":"${RFC7638_JWK.n}"}`;
  assert.equal(bytes.toString('utf8'), expected);
});

test('RFC 7638 §3.1: SHA-256 thumbprint matches the pinned value', async () => {
  assert.equal(await thumbprint(RFC7638_JWK), RFC7638_THUMBPRINT_SHA256);
});

test('RFC 7638 §3.1: thumbprint drops decorators (alg / kid ignored)', async () => {
  const bare = { kty: RFC7638_JWK.kty, n: RFC7638_JWK.n, e: RFC7638_JWK.e };
  assert.equal(await thumbprint(bare), RFC7638_THUMBPRINT_SHA256);
});

test('RFC 9278 §3: URI form wraps the spec thumbprint', async () => {
  const expected = `urn:ietf:params:oauth:jwk-thumbprint:sha-256:${RFC7638_THUMBPRINT_SHA256}`;
  assert.equal(await thumbprintURI(RFC7638_JWK), expected);
});

test('RFC 7638 required-member sets are lexicographically ordered', () => {
  // Canonical form depends on lexicographic key order; if these arrays
  // ever get reordered by mistake, thumbprints of every kty drift.
  for (const [, members] of Object.entries(REQUIRED_MEMBERS)) {
    const sorted = [...members].sort();
    assert.deepEqual([...members], sorted, `${members.join(',')} not lex-sorted`);
  }
});
