import { describe, test } from 'node:test';
import assert from 'node:assert/strict';

import { parseCookies, serialiseCookie, serialiseDeleteCookie } from '../src/cookie.js';

const toObj = m => Object.assign({}, m);

describe('parseCookies', () => {
  test('empty / non-string → {}', () => {
    assert.deepEqual(toObj(parseCookies('')), {});
    assert.deepEqual(toObj(parseCookies(null)), {});
    assert.deepEqual(toObj(parseCookies(undefined)), {});
    assert.deepEqual(toObj(parseCookies(42)), {});
  });

  test('single pair', () => {
    assert.deepEqual(toObj(parseCookies('sid=abc')), { sid: 'abc' });
  });

  test('multiple pairs, whitespace between', () => {
    assert.deepEqual(toObj(parseCookies('a=1; b=2;  c=3')), { a: '1', b: '2', c: '3' });
  });

  test('URL-decodes value', () => {
    assert.deepEqual(toObj(parseCookies('token=hello%20world')), { token: 'hello world' });
  });

  test('malformed percent encoding keeps raw value', () => {
    assert.deepEqual(toObj(parseCookies('t=%ZZ')), { t: '%ZZ' });
  });

  test('quoted value strips quotes', () => {
    assert.deepEqual(toObj(parseCookies('t="raw"')), { t: 'raw' });
  });

  test('duplicate names — first wins', () => {
    assert.deepEqual(toObj(parseCookies('a=1; a=2')), { a: '1' });
  });

  test('malformed segments skipped', () => {
    assert.deepEqual(toObj(parseCookies('=novalue; a=1; noequals; b=2')), { a: '1', b: '2' });
  });
});

describe('serialiseCookie', () => {
  test('basic pair with sensible defaults', () => {
    const s = serialiseCookie('sid', 'abc');
    assert.match(s, /^sid=abc; Path=\/; Secure; HttpOnly; SameSite=Lax$/);
  });

  test('URL-encodes value', () => {
    assert.match(serialiseCookie('t', 'a b'), /^t=a%20b;/);
  });

  test('rejects missing name', () => {
    assert.throws(() => serialiseCookie('', 'v'), /name is required/);
    assert.throws(() => serialiseCookie(null, 'v'));
  });

  test('rejects bad chars in name', () => {
    assert.throws(() => serialiseCookie('has space', 'v'), /disallowed characters/);
  });

  test('rejects invalid sameSite', () => {
    assert.throws(() => serialiseCookie('s', 'v', { sameSite: 'bogus' }), /sameSite must be/);
  });

  test('SameSite=None requires Secure', () => {
    assert.throws(() => serialiseCookie('s', 'v', { sameSite: 'none', secure: false }), /requires secure=true/);
  });

  test('__Host- prefix: Secure mandatory, no Domain, Path=/', () => {
    assert.throws(() => serialiseCookie('__Host-x', 'v', { secure: false }), /Secure is mandatory/);
    assert.throws(() => serialiseCookie('__Host-x', 'v', { domain: 'a.com' }), /Domain must NOT be set/);
    assert.throws(() => serialiseCookie('__Host-x', 'v', { path: '/sub' }), /Path must be '\/'/);
    assert.match(serialiseCookie('__Host-x', 'v'), /Path=\/; Secure/);
  });

  test('__Secure- prefix demands secure', () => {
    assert.throws(() => serialiseCookie('__Secure-x', 'v', { secure: false }), /__Secure- prefix — Secure is mandatory/);
  });

  test('rejects domain with unsafe chars', () => {
    assert.throws(() => serialiseCookie('s', 'v', { domain: 'evil;other=1' }));
  });

  test('rejects path with unsafe chars', () => {
    assert.throws(() => serialiseCookie('s', 'v', { path: '/a;b' }));
  });

  test('maxAge, expires, custom flags', () => {
    const s = serialiseCookie('s', 'v', {
      domain: 'a.com',
      path: '/api',
      maxAge: 3600.9,
      expires: new Date('2030-01-01T00:00:00Z'),
      secure: false,
      httpOnly: false,
      sameSite: 'strict',
    });
    assert.match(s, /Domain=a\.com/);
    assert.match(s, /Path=\/api/);
    assert.match(s, /Expires=/);
    assert.match(s, /Max-Age=3600$/m.compile ? /Max-Age=3600/ : /Max-Age=3600/);
    assert.doesNotMatch(s, /Secure/);
    assert.doesNotMatch(s, /HttpOnly/);
    assert.match(s, /SameSite=Strict/);
  });
});

describe('serialiseDeleteCookie', () => {
  test('emits Max-Age=0 + past Expires', () => {
    const s = serialiseDeleteCookie('sid');
    assert.match(s, /Max-Age=0/);
    assert.match(s, /Expires=Thu, 01 Jan 1970/);
  });
});
