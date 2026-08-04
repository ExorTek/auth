import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { test, before, after } from 'node:test';

import { ErrorCode, OAuth2Error } from '../src/index.js';
import { getJson, postForm } from '../src/internal/http.js';

/** @type {import('node:http').Server} */
let server;
/** @type {string} */
let base;
/** @type {(req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse) => void} */
let handler;

before(async () => {
  server = createServer((req, res) => handler(req, res));
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const { port } = /** @type {import('node:net').AddressInfo} */ (server.address());
  base = `http://127.0.0.1:${port}`;
});

after(() => new Promise(resolve => server.close(resolve)));

test('postForm sends a urlencoded body and parses JSON', async () => {
  /** @type {string} */
  let received;
  handler = (req, res) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      received = Buffer.concat(chunks).toString();
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ access_token: 'abc', token_type: 'Bearer' }));
    });
  };

  const body = await postForm(`${base}/token`, { grant_type: 'authorization_code', code: 'x y' });
  assert.equal(body.access_token, 'abc');
  assert.match(received, /grant_type=authorization_code/);
  assert.match(received, /code=x\+y/); // form-encoded space
});

test('getJson attaches a bearer token', async () => {
  handler = (req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ auth: req.headers.authorization }));
  };
  const body = await getJson(`${base}/userinfo`, { token: 'tok123' });
  assert.equal(body.auth, 'Bearer tok123');
});

test('a non-2xx response throws the caller-chosen code and surfaces `error`', async () => {
  handler = (_req, res) => {
    res.writeHead(400, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'invalid_grant' }));
  };
  await assert.rejects(postForm(`${base}/token`, {}), err => {
    assert.ok(err instanceof OAuth2Error);
    assert.equal(err.code, ErrorCode.TOKEN_EXCHANGE_FAILED);
    assert.match(err.message, /invalid_grant/);
    assert.equal(err.details?.error, 'invalid_grant');
    return true;
  });
});

test('a redirect is refused for SSRF safety', async () => {
  handler = (_req, res) => {
    res.writeHead(302, { location: 'http://169.254.169.254/' });
    res.end();
  };
  await assert.rejects(getJson(`${base}/userinfo`), err => {
    assert.equal(err.code, ErrorCode.USERINFO_FAILED);
    assert.match(err.message, /redirect/i);
    return true;
  });
});

test('an over-size response is rejected', async () => {
  handler = (_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ blob: 'x'.repeat(2000) }));
  };
  await assert.rejects(getJson(`${base}/userinfo`, {}, { maxResponseSize: 100 }), err => {
    assert.equal(err.code, ErrorCode.USERINFO_FAILED);
    assert.match(err.message, /maxResponseSize/);
    return true;
  });
});

test('a timeout surfaces as NETWORK_ERROR', async () => {
  handler = (_req, _res) => {
    /* never respond */
  };
  await assert.rejects(getJson(`${base}/userinfo`, {}, { timeout: 50 }), err => {
    assert.equal(err.code, ErrorCode.NETWORK_ERROR);
    assert.match(err.message, /timed out/);
    return true;
  });
});

test('a malformed JSON body throws the typed error', async () => {
  handler = (_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('not json');
  };
  await assert.rejects(getJson(`${base}/userinfo`), err => {
    assert.equal(err.code, ErrorCode.USERINFO_FAILED);
    assert.match(err.message, /non-JSON/);
    return true;
  });
});
