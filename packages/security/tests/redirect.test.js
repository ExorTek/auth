import { test } from 'node:test';
import assert from 'node:assert/strict';
import { safeRedirect, extractReturnUrl, isSameOrigin, SecurityError } from '../src/index.js';

// happy paths

test('safeRedirect: same-origin path is accepted verbatim', () => {
  const r = safeRedirect('/dashboard');
  assert.equal(r.safe, true);
  assert.equal(r.url, '/dashboard');
});

test('safeRedirect: same-origin path with query preserved', () => {
  const r = safeRedirect('/dashboard?tab=orders&page=2');
  assert.equal(r.safe, true);
  assert.equal(r.url, '/dashboard?tab=orders&page=2');
});

test('safeRedirect: absolute URL to allowlisted host', () => {
  const r = safeRedirect('https://app.example.com/settings', {
    allowedHosts: ['app.example.com'],
  });
  assert.equal(r.safe, true);
  assert.equal(r.url, 'https://app.example.com/settings');
});

test('safeRedirect: wildcard host matches subdomains but not apex', () => {
  const opt = { allowedHosts: ['*.example.com'] };
  assert.equal(safeRedirect('https://app.example.com/x', opt).safe, true);
  assert.equal(safeRedirect('https://a.b.example.com/x', opt).safe, true);
  // Apex domain does NOT match *.example.com.
  const apex = safeRedirect('https://example.com/x', opt);
  assert.equal(apex.safe, false);
  assert.equal(apex.reason, 'host');
});

// classic open-redirect vectors

test('safeRedirect: protocol-relative URL is rejected', () => {
  const r = safeRedirect('//evil.com/pwn');
  assert.equal(r.safe, false);
  assert.equal(r.reason, 'protocol-relative');
  assert.equal(r.url, '/');
});

test('safeRedirect: backslash tricks are rejected as illegal chars', () => {
  const r = safeRedirect('/\\evil.com');
  assert.equal(r.safe, false);
  assert.equal(r.reason, 'illegal-chars');
});

test('safeRedirect: javascript: scheme hard-banned even if allowlisted', () => {
  const r = safeRedirect('javascript:alert(1)', {
    allowedSchemes: ['javascript', 'http', 'https'],
    allowedHosts: ['*'],
  });
  assert.equal(r.safe, false);
  assert.equal(r.reason, 'scheme');
});

test('safeRedirect: data: scheme hard-banned', () => {
  const r = safeRedirect('data:text/html,<script>alert(1)</script>', {
    allowedSchemes: ['data'],
    allowedHosts: ['whatever'],
  });
  assert.equal(r.safe, false);
  assert.equal(r.reason, 'scheme');
});

test('safeRedirect: userinfo trick is rejected', () => {
  const r = safeRedirect('https://evil.com@app.example.com/', {
    allowedHosts: ['app.example.com'],
  });
  assert.equal(r.safe, false);
  assert.equal(r.reason, 'userinfo');
});

test('safeRedirect: control characters rejected', () => {
  assert.equal(safeRedirect('/foo\x00bar').reason, 'illegal-chars');
  assert.equal(safeRedirect('/foo\nbar').reason, 'illegal-chars');
});

test('safeRedirect: whitespace-prefixed URL rejected', () => {
  const r = safeRedirect(' https://app.example.com', { allowedHosts: ['app.example.com'] });
  assert.equal(r.safe, false);
  assert.equal(r.reason, 'illegal-chars');
});

// input validation

test('safeRedirect: empty / non-string input returns fallback', () => {
  assert.equal(safeRedirect(undefined).reason, 'empty');
  assert.equal(safeRedirect(null).reason, 'empty');
  assert.equal(safeRedirect('').reason, 'empty');
  assert.equal(safeRedirect(42).reason, 'empty');
});

test('safeRedirect: bare token (no leading /) is malformed', () => {
  const r = safeRedirect('dashboard/tab');
  assert.equal(r.safe, false);
  assert.equal(r.reason, 'malformed');
});

test('safeRedirect: cross-origin absolute rejected when no allowlist', () => {
  const r = safeRedirect('https://foo.com/');
  assert.equal(r.safe, false);
  assert.equal(r.reason, 'host');
});

test('safeRedirect: absolute to non-allowed host rejected', () => {
  const r = safeRedirect('https://evil.com/', { allowedHosts: ['app.example.com'] });
  assert.equal(r.safe, false);
  assert.equal(r.reason, 'host');
});

test('safeRedirect: scheme not in allowlist rejected', () => {
  const r = safeRedirect('ftp://files.example.com/x', {
    allowedHosts: ['files.example.com'],
  });
  assert.equal(r.safe, false);
  assert.equal(r.reason, 'scheme');
});

// options

test('safeRedirect: allowRelative=false rejects same-origin paths', () => {
  const r = safeRedirect('/dashboard', { allowRelative: false });
  assert.equal(r.safe, false);
  assert.equal(r.reason, 'relative-not-allowed');
});

test('safeRedirect: custom defaultTo returned on unsafe input', () => {
  const r = safeRedirect('//evil.com', { defaultTo: '/login' });
  assert.equal(r.url, '/login');
});

test('safeRedirect: rejects defaultTo that is not a same-origin path', () => {
  assert.throws(() => safeRedirect('/', { defaultTo: 'https://elsewhere.com' }), SecurityError);
  assert.throws(() => safeRedirect('/', { defaultTo: '' }), SecurityError);
});

test('safeRedirect: rejects non-string allowedHosts entries', () => {
  assert.throws(() => safeRedirect('/', { allowedHosts: [123] }), SecurityError);
  assert.throws(() => safeRedirect('/', { allowedHosts: [''] }), SecurityError);
});

test('safeRedirect: host matching is case-insensitive', () => {
  const r = safeRedirect('https://APP.Example.COM/x', {
    allowedHosts: ['app.example.com'],
  });
  assert.equal(r.safe, true);
});

test('safeRedirect: malformed URL falls back safely', () => {
  const r = safeRedirect('http://[not-a-host]', { allowedHosts: ['x'] });
  assert.equal(r.safe, false);
  assert.equal(r.reason, 'malformed');
});

// extractReturnUrl

test('extractReturnUrl: picks the first present query param in priority order', () => {
  const req = { query: { next: '/a', return_to: '/b' } };
  assert.equal(extractReturnUrl(req), '/a');
});

test('extractReturnUrl: falls through when a param is empty', () => {
  const req = { query: { next: '', return_to: '/dashboard' } };
  assert.equal(extractReturnUrl(req), '/dashboard');
});

test('extractReturnUrl: custom param list', () => {
  const req = { query: { goto: '/x' } };
  assert.equal(extractReturnUrl(req, { queryParams: ['goto'] }), '/x');
});

test('extractReturnUrl: falls back to header', () => {
  const req = { query: {}, headers: { 'x-return-to': '/from-header' } };
  assert.equal(extractReturnUrl(req, { headerName: 'X-Return-To' }), '/from-header');
});

test('extractReturnUrl: falls back to cookie', () => {
  const req = { query: {}, headers: {}, cookies: { return_to: '/from-cookie' } };
  assert.equal(extractReturnUrl(req, { cookieName: 'return_to' }), '/from-cookie');
});

test('extractReturnUrl: returns undefined when nothing found', () => {
  assert.equal(extractReturnUrl({}), undefined);
  assert.equal(extractReturnUrl({ query: {}, headers: {} }), undefined);
});

test('extractReturnUrl: takes first entry when framework parses as array', () => {
  const req = { query: { next: ['/first', '/second'] } };
  assert.equal(extractReturnUrl(req), '/first');
});

// isSameOrigin

test('isSameOrigin: same origin returns true regardless of path', () => {
  assert.equal(isSameOrigin('https://example.com/a', 'https://example.com/b?x=1'), true);
  assert.equal(isSameOrigin('https://example.com:443/x', 'https://example.com/y'), true);
});

test('isSameOrigin: different scheme, host, or port returns false', () => {
  assert.equal(isSameOrigin('https://example.com', 'http://example.com'), false);
  assert.equal(isSameOrigin('https://example.com', 'https://other.com'), false);
  assert.equal(isSameOrigin('https://example.com', 'https://example.com:8443'), false);
});

test('isSameOrigin: accepts URL objects', () => {
  assert.equal(isSameOrigin(new URL('https://x.com/a'), new URL('https://x.com/b')), true);
});

test('isSameOrigin: null / undefined / malformed → false', () => {
  assert.equal(isSameOrigin(null, 'https://x'), false);
  assert.equal(isSameOrigin('https://x', undefined), false);
  assert.equal(isSameOrigin('not-a-url', 'https://x'), false);
});
