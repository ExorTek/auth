/**
 * Test helpers for synthesising realistic WebAuthn responses without
 * running a real authenticator. We hand-assemble CBOR (matching the
 * decoder's contract) and produce a signed attestation object so
 * end-to-end verification exercises the full pipeline.
 */

import { createHash, createSign, generateKeyPairSync, sign as ed25519Sign } from 'node:crypto';
import { base64url } from '@exortek/crypto/encode';

export function concat(...chunks) {
  const total = chunks.reduce((n, c) => n + c.byteLength, 0);
  const out = new Uint8Array(total);
  let pos = 0;
  for (const c of chunks) {
    out.set(c, pos);
    pos += c.byteLength;
  }
  return out;
}

export function hex(str) {
  const clean = str.replace(/\s+/g, '');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

// Minimal CBOR encoder — just enough for our fixture assembly.
// Covers uints, negative ints, byte strings, text strings, arrays,
// definite-length maps, and `true`/`false`/`null`.
export function cborEncode(value) {
  if (typeof value === 'number' && Number.isInteger(value)) {
    return value >= 0 ? cborHead(0, value) : cborHead(1, -1 - value);
  }
  if (typeof value === 'string') {
    const bytes = new TextEncoder().encode(value);
    return concat(cborHead(3, bytes.byteLength), bytes);
  }
  if (value instanceof Uint8Array) {
    return concat(cborHead(2, value.byteLength), value);
  }
  if (Array.isArray(value)) {
    return concat(cborHead(4, value.length), ...value.map(cborEncode));
  }
  if (value instanceof Map) {
    const parts = [cborHead(5, value.size)];
    for (const [k, v] of value) {
      parts.push(cborEncode(k), cborEncode(v));
    }
    return concat(...parts);
  }
  if (value === true) return hex('f5');
  if (value === false) return hex('f4');
  if (value === null) return hex('f6');
  throw new Error(`cborEncode: unsupported value ${typeof value}`);
}

function cborHead(major, n) {
  const prefix = major << 5;
  if (n < 24) return new Uint8Array([prefix | n]);
  if (n < 0x100) return new Uint8Array([prefix | 24, n]);
  if (n < 0x10000) return new Uint8Array([prefix | 25, n >> 8, n & 0xff]);
  if (n < 0x100000000) {
    return new Uint8Array([prefix | 26, (n >> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]);
  }
  throw new Error('cborHead: length too big for the test encoder');
}

// COSE key encoders for ES256 / EdDSA / RS256.
export function coseEs256(x, y) {
  const m = new Map();
  m.set(1, 2); // kty=EC2
  m.set(3, -7); // alg=ES256
  m.set(-1, 1); // crv=P-256
  m.set(-2, x);
  m.set(-3, y);
  return m;
}

export function coseEdDsa(x) {
  const m = new Map();
  m.set(1, 1); // kty=OKP
  m.set(3, -8); // alg=EdDSA
  m.set(-1, 6); // crv=Ed25519
  m.set(-2, x);
  return m;
}

export function coseRs256(n, e) {
  const m = new Map();
  m.set(1, 3); // kty=RSA
  m.set(3, -257); // alg=RS256
  m.set(-1, n);
  m.set(-2, e);
  return m;
}

// authData assembly.
export function makeAuthData({ rpId, flags = 0x45, counter = 0, aaguid, credentialId, coseKey, extensionsBytes }) {
  const rpIdHash = new Uint8Array(createHash('sha256').update(rpId).digest());
  const counterBytes = new Uint8Array(4);
  new DataView(counterBytes.buffer).setUint32(0, counter, false);
  const parts = [rpIdHash, new Uint8Array([flags]), counterBytes];
  if (flags & 0x40) {
    if (!aaguid || aaguid.byteLength !== 16) {
      throw new Error('makeAuthData: AT flag set — aaguid must be 16 bytes');
    }
    const credIdLen = new Uint8Array(2);
    new DataView(credIdLen.buffer).setUint16(0, credentialId.byteLength, false);
    parts.push(aaguid, credIdLen, credentialId, cborEncode(coseKey));
  }
  if (flags & 0x80) {
    parts.push(extensionsBytes);
  }
  return concat(...parts);
}

// clientDataJSON assembly.
export function makeClientDataJSON({ type, challengeBase64Url, origin, crossOrigin }) {
  const obj = { type, challenge: challengeBase64Url, origin };
  if (crossOrigin !== undefined) obj.crossOrigin = crossOrigin;
  return new TextEncoder().encode(JSON.stringify(obj));
}

/**
 * Build a full registration response with `fmt: "none"`.
 */
export function makeNoneResponse({ rpId, challengeBase64Url, origin, algorithm = 'es256', flags = 0x45 }) {
  const { publicKey, privateKey, jwk, coseKey } = genKeyPair(algorithm);
  const credentialId = hex('abcdef0123456789');
  const authDataBytes = makeAuthData({
    rpId,
    flags,
    counter: 0,
    aaguid: hex('00112233445566778899aabbccddeeff'),
    credentialId,
    coseKey,
  });
  const attestationObject = cborEncode(
    new Map([
      ['fmt', 'none'],
      ['authData', authDataBytes],
      ['attStmt', new Map()],
    ]),
  );
  const clientDataJSON = makeClientDataJSON({ type: 'webauthn.create', challengeBase64Url, origin });
  return {
    response: {
      id: base64url.encode(credentialId),
      rawId: base64url.encode(credentialId),
      type: 'public-key',
      response: {
        clientDataJSON: base64url.encode(clientDataJSON),
        attestationObject: base64url.encode(attestationObject),
      },
    },
    publicKey,
    privateKey,
    jwk,
    coseKey,
    credentialId,
    authDataBytes,
    clientDataJSON,
  };
}

/**
 * Build a packed self-attestation registration response.
 */
export function makePackedSelfResponse({ rpId, challengeBase64Url, origin }) {
  const { publicKey, privateKey, jwk, coseKey } = genKeyPair('es256');
  const credentialId = hex('deadbeefcafeface');
  const authDataBytes = makeAuthData({
    rpId,
    flags: 0x45,
    counter: 0,
    aaguid: hex('00000000000000000000000000000000'),
    credentialId,
    coseKey,
  });
  const clientDataJSON = makeClientDataJSON({ type: 'webauthn.create', challengeBase64Url, origin });
  const clientDataHash = new Uint8Array(createHash('sha256').update(clientDataJSON).digest());
  const signed = concat(authDataBytes, clientDataHash);
  const sig = createSign('SHA256').update(signed).sign({ key: privateKey, dsaEncoding: 'der' });

  const attStmt = new Map([
    ['alg', -7],
    ['sig', new Uint8Array(sig)],
  ]);
  const attestationObject = cborEncode(
    new Map([
      ['fmt', 'packed'],
      ['authData', authDataBytes],
      ['attStmt', attStmt],
    ]),
  );

  return {
    response: {
      id: base64url.encode(credentialId),
      rawId: base64url.encode(credentialId),
      type: 'public-key',
      response: {
        clientDataJSON: base64url.encode(clientDataJSON),
        attestationObject: base64url.encode(attestationObject),
      },
    },
    publicKey,
    privateKey,
    jwk,
    coseKey,
    credentialId,
    authDataBytes,
    clientDataJSON,
  };
}

/**
 * Build an authentication (assertion) response signed by `privateKey`.
 */
export function makeAssertionResponse({
  rpId,
  challengeBase64Url,
  origin,
  privateKey,
  algorithm = 'es256',
  counter = 1,
  credentialId,
  flags = 0x05,
}) {
  const authDataBytes = makeAuthData({ rpId, flags, counter });
  const clientDataJSON = makeClientDataJSON({ type: 'webauthn.get', challengeBase64Url, origin });
  const clientDataHash = new Uint8Array(createHash('sha256').update(clientDataJSON).digest());
  const signed = concat(authDataBytes, clientDataHash);

  let sigBytes;
  if (algorithm === 'ed25519') {
    sigBytes = ed25519Sign(null, signed, privateKey);
  } else {
    sigBytes = createSign('SHA256').update(signed).sign({ key: privateKey, dsaEncoding: 'der' });
  }

  return {
    id: base64url.encode(credentialId),
    rawId: base64url.encode(credentialId),
    type: 'public-key',
    response: {
      clientDataJSON: base64url.encode(clientDataJSON),
      authenticatorData: base64url.encode(authDataBytes),
      signature: base64url.encode(new Uint8Array(sigBytes)),
    },
  };
}

function genKeyPair(kind) {
  if (kind === 'es256') {
    const kp = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const jwk = kp.publicKey.export({ format: 'jwk' });
    const coseKey = coseEs256(new Uint8Array(base64url.decode(jwk.x)), new Uint8Array(base64url.decode(jwk.y)));
    return { publicKey: kp.publicKey, privateKey: kp.privateKey, jwk, coseKey };
  }
  if (kind === 'ed25519') {
    const kp = generateKeyPairSync('ed25519');
    const jwk = kp.publicKey.export({ format: 'jwk' });
    const coseKey = coseEdDsa(new Uint8Array(base64url.decode(jwk.x)));
    return { publicKey: kp.publicKey, privateKey: kp.privateKey, jwk, coseKey };
  }
  throw new Error(`genKeyPair: unsupported kind ${kind}`);
}
