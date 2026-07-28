import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { base64url } from '@exortek/crypto/encode';
import { formatAaguid, parseAuthData } from '../../src/webauthn/authData.js';

function concat(...chunks) {
  const total = chunks.reduce((n, c) => n + c.byteLength, 0);
  const out = new Uint8Array(total);
  let pos = 0;
  for (const c of chunks) {
    out.set(c, pos);
    pos += c.byteLength;
  }
  return out;
}

function h(hex) {
  const clean = hex.replace(/\s+/g, '');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * Encode a minimal ES256 COSE Key Map by hand. Independent of our
 * decoder — we test the parser, not a roundtrip against itself.
 * Layout:
 *   a5              map(5)
 *   01 02           kty (1) = EC2 (2)
 *   03 26           alg (3) = -7 (ES256)
 *   20 01           crv (-1) = P-256 (1)
 *   21 58 20 <32>   x  (-2) = bytes(32)
 *   22 58 20 <32>   y  (-3) = bytes(32)
 */
function encodeCoseEs256(x, y) {
  if (x.byteLength !== 32 || y.byteLength !== 32) {
    throw new Error('encodeCoseEs256: coordinates must be 32 bytes each');
  }
  return concat(h('a5' + '0102' + '0326' + '2001' + '215820'), x, h('225820'), y);
}

const RP_ID = 'example.com';
const RP_ID_HASH = new Uint8Array(createHash('sha256').update(RP_ID).digest());

describe('authData — formatAaguid', () => {
  test('all-zero AAGUID', () => {
    assert.equal(formatAaguid(new Uint8Array(16)), '00000000-0000-0000-0000-000000000000');
  });

  test('canonical hyphen layout', () => {
    const bytes = h('01020304' + '0506' + '0708' + '090a' + '0b0c0d0e0f10');
    assert.equal(formatAaguid(bytes), '01020304-0506-0708-090a-0b0c0d0e0f10');
  });

  test('rejects wrong length', () => {
    assert.throws(() => formatAaguid(new Uint8Array(15)), /16-byte/);
  });
});

describe('authData — assertion-shape (no attested credential data)', () => {
  test('parses rpIdHash + flags + counter', () => {
    const bytes = concat(RP_ID_HASH, h('05'), h('00000042')); // UP+UV, counter=66
    const out = parseAuthData(bytes);
    assert.deepEqual(out.rpIdHash, RP_ID_HASH);
    assert.equal(out.flags.up, true);
    assert.equal(out.flags.uv, true);
    assert.equal(out.flags.at, false);
    assert.equal(out.signCount, 66);
    assert.equal(out.attestedCredentialData, null);
    assert.equal(out.extensions, null);
  });

  test('rejects too-short input', () => {
    assert.throws(() => parseAuthData(new Uint8Array(36)), /too short/);
  });

  test('rejects non-Uint8Array', () => {
    assert.throws(() => parseAuthData([]), /Uint8Array/);
  });

  test('rejects trailing bytes on an assertion-shape buffer', () => {
    const bytes = concat(RP_ID_HASH, h('05'), h('00000042'), h('deadbeef'));
    assert.throws(() => parseAuthData(bytes), /trailing/);
  });
});

describe('authData — registration-shape (AT flag set)', () => {
  function buildRegistrationAuthData({ credentialId, coseKey, flagsByte = 0x45, counter = 0 }) {
    const counterBytes = new Uint8Array(4);
    new DataView(counterBytes.buffer).setUint32(0, counter, false);
    const aaguid = h('00112233445566778899aabbccddeeff');
    const credLen = new Uint8Array(2);
    new DataView(credLen.buffer).setUint16(0, credentialId.byteLength, false);
    return concat(RP_ID_HASH, new Uint8Array([flagsByte]), counterBytes, aaguid, credLen, credentialId, coseKey);
  }

  test('parses aaguid + credentialId + credentialPublicKey', () => {
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const jwk = publicKey.export({ format: 'jwk' });
    const cose = encodeCoseEs256(new Uint8Array(base64url.decode(jwk.x)), new Uint8Array(base64url.decode(jwk.y)));
    const credentialId = h('abcdef0123456789');
    const bytes = buildRegistrationAuthData({ credentialId, coseKey: cose });

    const out = parseAuthData(bytes);
    assert.deepEqual(out.rpIdHash, RP_ID_HASH);
    assert.equal(out.flags.at, true);
    assert.equal(out.flags.up, true);
    assert.equal(out.flags.uv, true);
    assert.equal(out.attestedCredentialData.aaguidString, '00112233-4455-6677-8899-aabbccddeeff');
    assert.deepEqual(out.attestedCredentialData.credentialId, credentialId);
    assert.ok(out.attestedCredentialData.credentialPublicKey instanceof Map);
    assert.equal(out.attestedCredentialData.credentialPublicKey.get(3), -7);
    // Raw key bytes captured for downstream re-hash use.
    assert.deepEqual(out.attestedCredentialData.credentialPublicKeyBytes, cose);
  });

  test('AT flag with truncated credential data throws', () => {
    // AT=0x40 set but body has only rpIdHash + flags + counter.
    const bytes = concat(RP_ID_HASH, h('41'), h('00000000'));
    assert.throws(() => parseAuthData(bytes), /truncated/);
  });

  test('credentialIdLength=0 throws', () => {
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const jwk = publicKey.export({ format: 'jwk' });
    const cose = encodeCoseEs256(new Uint8Array(base64url.decode(jwk.x)), new Uint8Array(base64url.decode(jwk.y)));
    const bytes = concat(RP_ID_HASH, h('45'), h('00000000'), h('00112233445566778899aabbccddeeff'), h('0000'), cose);
    assert.throws(() => parseAuthData(bytes), /credentialIdLength is 0/);
  });

  test('credentialIdLength above CTAP2 max (1023) throws', () => {
    // credLen field = 0x0400 = 1024, exceeds the CTAP2 limit.
    const bytes = concat(
      RP_ID_HASH,
      h('45'),
      h('00000000'),
      h('00112233445566778899aabbccddeeff'),
      h('0400'),
      new Uint8Array(0),
    );
    assert.throws(() => parseAuthData(bytes), /exceeds CTAP2/);
  });

  test('credentialId declared beyond available bytes throws', () => {
    const bytes = concat(
      RP_ID_HASH,
      h('45'),
      h('00000000'),
      h('00112233445566778899aabbccddeeff'),
      h('0010'),
      new Uint8Array(4),
    );
    assert.throws(() => parseAuthData(bytes), /only \d+ left/);
  });
});

describe('authData — extensions (ED flag)', () => {
  test('parses an ED-only extension map', () => {
    // 0x81 = UP + ED. No AT, so extensions start right after counter.
    // CBOR: a1 6b 68 6d 61 63 2d 73 65 63 72 65 74 f5 =
    //   map(1) { "hmac-secret": true }
    const extMap = h('a1' + '6b' + '686d61632d736563726574' + 'f5');
    const bytes = concat(RP_ID_HASH, h('81'), h('00000000'), extMap);
    const out = parseAuthData(bytes);
    assert.equal(out.flags.ed, true);
    assert.ok(out.extensions instanceof Map);
    assert.equal(out.extensions.get('hmac-secret'), true);
  });

  test('ED flag set but no bytes after → throws', () => {
    const bytes = concat(RP_ID_HASH, h('81'), h('00000000'));
    assert.throws(() => parseAuthData(bytes), /extensions block missing/);
  });
});
