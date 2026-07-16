import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes } from 'node:crypto';

import { sign, verify, decode, JwsError, ErrorCode } from '../src/index.js';

// -- Helpers ---------------------------------------------------------

function ecP256() {
  return generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
}

// -- Roundtrip -------------------------------------------------------

test('b64:false — HS256 roundtrip preserves raw payload verbatim', async () => {
  const secret = randomBytes(32);
  const token = await sign('hello world', secret, { alg: 'HS256', b64: false });
  const parts = token.split('.');
  assert.equal(parts[1], 'hello world', 'segment must be the raw payload');
  const { payload, header } = await verify(token, secret, { alg: ['HS256'] });
  assert.equal(payload, 'hello world', 'verify returns the raw string for b64:false');
  assert.equal(header.b64, false);
  assert.deepEqual(header.crit, ['b64']);
});

test('b64:false — Buffer payload passes through as UTF-8', async () => {
  const secret = randomBytes(32);
  const token = await sign(Buffer.from('raw bytes here'), secret, {
    alg: 'HS256',
    b64: false,
  });
  const { payload } = await verify(token, secret, { alg: ['HS256'] });
  assert.equal(payload, 'raw bytes here');
});

test('b64:false — ES256 roundtrip', async () => {
  const { publicKey, privateKey } = ecP256();
  const token = await sign('unencoded', privateKey, { alg: 'ES256', b64: false });
  const { payload } = await verify(token, publicKey, { alg: ['ES256'] });
  assert.equal(payload, 'unencoded');
});

// -- Header + crit management ----------------------------------------

test('b64:false — sets header.b64=false and adds "b64" to crit', async () => {
  const secret = randomBytes(32);
  const token = await sign('x', secret, { alg: 'HS256', b64: false });
  const { header } = decode(token);
  assert.equal(header.b64, false);
  assert.deepEqual(header.crit, ['b64']);
});

test('b64:false — merges "b64" into caller-supplied crit array', async () => {
  const secret = randomBytes(32);
  const token = await sign('x', secret, {
    alg: 'HS256',
    b64: false,
    crit: ['ourcustom'],
    header: { ourcustom: 'v' },
  });
  const { header } = decode(token);
  assert.deepEqual(header.crit, ['ourcustom', 'b64']);
});

test('b64:false — does not duplicate "b64" if caller already included it', async () => {
  const secret = randomBytes(32);
  const token = await sign('x', secret, {
    alg: 'HS256',
    b64: false,
    crit: ['b64'],
  });
  const { header } = decode(token);
  assert.deepEqual(header.crit, ['b64']);
});

test('b64:false — non-array crit is rejected with INVALID_HEADER', async () => {
  const secret = randomBytes(32);
  await assert.rejects(
    () =>
      sign('x', secret, {
        alg: 'HS256',
        b64: false,
        crit: /** @type {any} */ ('not an array'),
      }),
    err => err instanceof JwsError && err.code === ErrorCode.INVALID_HEADER,
  );
});

// -- '.' guard -------------------------------------------------------

test('b64:false — payload containing "." raises INVALID_PAYLOAD', async () => {
  const secret = randomBytes(32);
  await assert.rejects(
    () => sign('bad.payload', secret, { alg: 'HS256', b64: false }),
    err => err instanceof JwsError && err.code === ErrorCode.INVALID_PAYLOAD,
  );
});

test('b64:false — Buffer payload containing 0x2E raises INVALID_PAYLOAD', async () => {
  const secret = randomBytes(32);
  await assert.rejects(
    () => sign(Buffer.from([0x61, 0x2e, 0x62]), secret, { alg: 'HS256', b64: false }),
    err => err instanceof JwsError && err.code === ErrorCode.INVALID_PAYLOAD,
  );
});

// -- Verify: tamper detection stays honest under b64:false -----------

test('b64:false — payload tamper flips INVALID_SIGNATURE', async () => {
  const secret = randomBytes(32);
  const token = await sign('trusted', secret, { alg: 'HS256', b64: false });
  const parts = token.split('.');
  const tampered = `${parts[0]}.impostor.${parts[2]}`;
  await assert.rejects(
    () => verify(tampered, secret, { alg: ['HS256'] }),
    err => err instanceof JwsError && err.code === ErrorCode.INVALID_SIGNATURE,
  );
});

// -- Verify surface still enforces the security invariants -----------

test('b64:false — verify still requires an alg allowlist', async () => {
  const secret = randomBytes(32);
  const token = await sign('x', secret, { alg: 'HS256', b64: false });
  await assert.rejects(
    () => verify(token, secret, /** @type {any} */ (undefined)),
    err => err instanceof JwsError && err.code === ErrorCode.MISSING_ALG_ALLOWLIST,
  );
});

test('b64:false — verify without "b64" in knownCriticalHeaders still works (b64 is built-in)', async () => {
  const secret = randomBytes(32);
  const token = await sign('x', secret, { alg: 'HS256', b64: false });
  // KNOWN_CRIT built-in includes 'b64'; no extra opt-in needed.
  const { payload } = await verify(token, secret, { alg: ['HS256'] });
  assert.equal(payload, 'x');
});

// -- Default remains b64:true ----------------------------------------

test('b64:false is opt-in — omitting it keeps standard base64url payload', async () => {
  const secret = randomBytes(32);
  const token = await sign({ hi: 'there' }, secret, { alg: 'HS256' });
  const { header } = decode(token);
  assert.equal(header.b64, undefined);
  assert.equal(header.crit, undefined);
});
