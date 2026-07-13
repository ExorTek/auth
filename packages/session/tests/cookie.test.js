import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseCookies, serialiseCookie, serialiseDeleteCookie } from '../src/cookie.js';
import { SessionError, ErrorCode } from '../src/errors.js';

// `parseCookies` returns a null-prototype object as a defence against
// prototype-pollution via cookie names — spread into a plain object
// before deep-comparing, otherwise `deepStrictEqual` catches the
// prototype difference.
const plain = obj => ({ ...obj });

test('parseCookies: basic single cookie', () => {
  assert.deepEqual(plain(parseCookies('sid=abc')), { sid: 'abc' });
});

test('parseCookies: multiple cookies', () => {
  assert.deepEqual(plain(parseCookies('sid=abc; csrf=xyz')), { sid: 'abc', csrf: 'xyz' });
});

test('parseCookies: URL-encoded values', () => {
  assert.deepEqual(plain(parseCookies('a=hello%20world')), { a: 'hello world' });
});

test('parseCookies: quoted values', () => {
  assert.deepEqual(plain(parseCookies('a="quoted"')), { a: 'quoted' });
});

test('parseCookies: null / empty / non-string → empty map', () => {
  assert.deepEqual(plain(parseCookies(null)), {});
  assert.deepEqual(plain(parseCookies(undefined)), {});
  assert.deepEqual(plain(parseCookies('')), {});
  assert.deepEqual(plain(parseCookies(42)), {});
});

test('parseCookies: malformed segments skipped', () => {
  assert.deepEqual(plain(parseCookies('=novalue; onlyname; ok=1')), { ok: '1' });
});

test('parseCookies: first occurrence wins on duplicates', () => {
  assert.deepEqual(plain(parseCookies('sid=first; sid=second')), { sid: 'first' });
});

test('parseCookies: malformed percent encoding keeps raw', () => {
  assert.deepEqual(plain(parseCookies('a=%GG')), { a: '%GG' });
});

test('serialiseCookie: default flags', () => {
  const s = serialiseCookie('sid', 'abc');
  assert.match(s, /^sid=abc; Path=\/; Secure; HttpOnly; SameSite=Lax$/);
});

test('serialiseCookie: honours maxAge', () => {
  const s = serialiseCookie('sid', 'abc', { maxAge: 3600 });
  assert.match(s, /Max-Age=3600/);
});

test('serialiseCookie: honours expires', () => {
  const d = new Date('2030-01-01T00:00:00Z');
  const s = serialiseCookie('sid', 'abc', { expires: d });
  assert.ok(s.includes(`Expires=${d.toUTCString()}`));
});

test('serialiseCookie: URL-encodes values', () => {
  const s = serialiseCookie('sid', 'a b');
  assert.match(s, /sid=a%20b/);
});

test('serialiseCookie: SameSite=none requires secure', () => {
  assert.throws(
    () => serialiseCookie('sid', 'abc', { sameSite: 'none', secure: false }),
    err => err instanceof SessionError && err.code === ErrorCode.INVALID_ARGUMENT,
  );
});

test('serialiseCookie: __Host- prefix demands Secure', () => {
  assert.throws(
    () => serialiseCookie('__Host-sid', 'abc', { secure: false }),
    err => err instanceof SessionError && err.code === ErrorCode.INVALID_ARGUMENT,
  );
});

test('serialiseCookie: __Host- prefix forbids Domain', () => {
  assert.throws(
    () => serialiseCookie('__Host-sid', 'abc', { domain: 'example.com' }),
    err => err instanceof SessionError && err.code === ErrorCode.INVALID_ARGUMENT,
  );
});

test('serialiseCookie: __Host- prefix demands Path=/', () => {
  assert.throws(
    () => serialiseCookie('__Host-sid', 'abc', { path: '/api' }),
    err => err instanceof SessionError && err.code === ErrorCode.INVALID_ARGUMENT,
  );
});

test('serialiseCookie: __Secure- prefix demands Secure', () => {
  assert.throws(
    () => serialiseCookie('__Secure-sid', 'abc', { secure: false }),
    err => err instanceof SessionError && err.code === ErrorCode.INVALID_ARGUMENT,
  );
});

test('serialiseCookie: rejects bad name characters', () => {
  assert.throws(
    () => serialiseCookie('bad name', 'abc'),
    err => err instanceof SessionError && err.code === ErrorCode.INVALID_ARGUMENT,
  );
});

test('serialiseCookie: rejects bad sameSite', () => {
  assert.throws(() => serialiseCookie('sid', 'abc', { sameSite: 'weird' }));
});

test('serialiseDeleteCookie: emits Max-Age=0 + past Expires', () => {
  const s = serialiseDeleteCookie('sid');
  assert.match(s, /Max-Age=0/);
  assert.match(s, /Expires=Thu, 01 Jan 1970/);
});
