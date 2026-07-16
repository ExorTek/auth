import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes } from 'node:crypto';

import { sign, verify, JwsError, ErrorCode } from '../src/index.js';

function ecP256() {
  return generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
}

// JWK object
test('resolver: single JWK object → verify accepts', async () => {
  const { publicKey, privateKey } = ecP256();
  const token = await sign({ hi: 'there' }, privateKey, { alg: 'ES256' });
  const jwk = publicKey.export({ format: 'jwk' });
  const { payload } = await verify(token, jwk, { alg: ['ES256'] });
  assert.deepEqual(payload, { hi: 'there' });
});

test('resolver: single Buffer for HMAC', async () => {
  const secret = randomBytes(32);
  const token = await sign({ x: 1 }, secret, { alg: 'HS256' });
  const { payload } = await verify(token, secret, { alg: ['HS256'] });
  assert.deepEqual(payload, { x: 1 });
});

test('resolver: single oct JWK for HMAC', async () => {
  const secret = randomBytes(32);
  const token = await sign({ x: 1 }, secret, { alg: 'HS256' });
  const jwk = { kty: 'oct', k: secret.toString('base64url') };
  const { payload } = await verify(token, jwk, { alg: ['HS256'] });
  assert.deepEqual(payload, { x: 1 });
});

// JWK array (JWKS-like)
test('resolver: JWK array with matching kid resolves the right key', async () => {
  const a = ecP256();
  const b = ecP256();
  const token = await sign({ user: 'me' }, b.privateKey, { alg: 'ES256', kid: 'b' });
  const set = [
    { ...a.publicKey.export({ format: 'jwk' }), kid: 'a' },
    { ...b.publicKey.export({ format: 'jwk' }), kid: 'b' },
  ];
  const { header, payload } = await verify(token, set, { alg: ['ES256'] });
  assert.equal(header.kid, 'b');
  assert.deepEqual(payload, { user: 'me' });
});

test('resolver: JWK array with no matching kid raises KEY_NOT_FOUND', async () => {
  const a = ecP256();
  const b = ecP256();
  const token = await sign({}, b.privateKey, { alg: 'ES256', kid: 'unknown-kid' });
  await assert.rejects(
    () => verify(token, [{ ...a.publicKey.export({ format: 'jwk' }), kid: 'a' }], { alg: ['ES256'] }),
    err => err instanceof JwsError && err.code === ErrorCode.KEY_NOT_FOUND,
  );
});

test('resolver: JWK array with one key + no kid still resolves', async () => {
  const { publicKey, privateKey } = ecP256();
  const token = await sign({}, privateKey, { alg: 'ES256' }); // no kid
  const { header } = await verify(token, [publicKey.export({ format: 'jwk' })], {
    alg: ['ES256'],
  });
  assert.equal(header.alg, 'ES256');
});

test('resolver: JWK array with multiple keys + no kid on token raises KEY_NOT_FOUND', async () => {
  const a = ecP256();
  const b = ecP256();
  const token = await sign({}, a.privateKey, { alg: 'ES256' }); // no kid
  await assert.rejects(
    () =>
      verify(token, [a.publicKey.export({ format: 'jwk' }), b.publicKey.export({ format: 'jwk' })], { alg: ['ES256'] }),
    err => err instanceof JwsError && err.code === ErrorCode.KEY_NOT_FOUND,
  );
});

test('resolver: empty JWK array raises KEY_NOT_FOUND', async () => {
  const { privateKey } = ecP256();
  const token = await sign({}, privateKey, { alg: 'ES256' });
  await assert.rejects(
    () => verify(token, [], { alg: ['ES256'] }),
    err => err instanceof JwsError && err.code === ErrorCode.KEY_NOT_FOUND,
  );
});

// Async resolver function
test('resolver: async (header) => key — kid-driven lookup', async () => {
  const { publicKey, privateKey } = ecP256();
  const token = await sign({ ok: true }, privateKey, { alg: 'ES256', kid: 'lookup-me' });

  const store = new Map([['lookup-me', publicKey.export({ format: 'jwk' })]]);
  const resolver = async header => {
    const jwk = store.get(header.kid);
    if (!jwk) throw new JwsError(ErrorCode.KEY_NOT_FOUND, `no jwk for kid=${header.kid}`);
    return jwk;
  };

  const { payload } = await verify(token, resolver, { alg: ['ES256'] });
  assert.deepEqual(payload, { ok: true });
});

test('resolver: async function receives the parsed header (kid + alg)', async () => {
  const { publicKey, privateKey } = ecP256();
  const token = await sign({}, privateKey, { alg: 'ES256', kid: 'x' });

  let seenHeader;
  const resolver = async header => {
    seenHeader = header;
    return publicKey.export({ format: 'jwk' });
  };

  await verify(token, resolver, { alg: ['ES256'] });
  assert.equal(seenHeader.alg, 'ES256');
  assert.equal(seenHeader.kid, 'x');
});

test('resolver: async function returning a bad key surfaces INVALID_KEY', async () => {
  const { privateKey } = ecP256();
  const rsaKey = generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey;
  const token = await sign({}, privateKey, { alg: 'ES256' });
  await assert.rejects(
    () => verify(token, async () => rsaKey, { alg: ['ES256'] }),
    err => err instanceof JwsError && err.code === ErrorCode.INVALID_KEY,
  );
});

test('resolver: sync fn that throws bubbles up unchanged', async () => {
  const { privateKey } = ecP256();
  const token = await sign({}, privateKey, { alg: 'ES256' });
  await assert.rejects(
    () =>
      verify(
        token,
        () => {
          throw new JwsError(ErrorCode.KEY_NOT_FOUND, 'store is empty');
        },
        { alg: ['ES256'] },
      ),
    err => err instanceof JwsError && err.code === ErrorCode.KEY_NOT_FOUND,
  );
});
