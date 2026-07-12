import { test } from 'node:test';
import assert from 'node:assert/strict';
import { headers, cspNonce, SecurityError } from '../src/index.js';

// defaults

test('headers(): ships secure defaults', () => {
  const h = headers();
  assert.equal(h['X-Content-Type-Options'], 'nosniff');
  assert.equal(h['X-Frame-Options'], 'DENY');
  assert.equal(h['X-XSS-Protection'], '0');
  assert.equal(h['X-DNS-Prefetch-Control'], 'off');
  assert.equal(h['X-Download-Options'], 'noopen');
  assert.equal(h['X-Permitted-Cross-Domain-Policies'], 'none');
  assert.equal(h['Origin-Agent-Cluster'], '?1');
  assert.equal(h['Cross-Origin-Opener-Policy'], 'same-origin');
  assert.equal(h['Cross-Origin-Embedder-Policy'], 'require-corp');
  assert.equal(h['Cross-Origin-Resource-Policy'], 'same-origin');
  assert.equal(h['Referrer-Policy'], 'no-referrer');
  assert.ok(h['Strict-Transport-Security']);
  assert.ok(h['Content-Security-Policy']);
});

test('headers(): permissionsPolicy is opt-in (not in defaults)', () => {
  const h = headers();
  assert.equal(h['Permissions-Policy'], undefined);
});

// opt-out

test('headers(): each policy can be disabled with false', () => {
  const h = headers({
    contentSecurityPolicy: false,
    hsts: false,
    contentTypeOptions: false,
    frameguard: false,
    crossOriginEmbedderPolicy: false,
    referrerPolicy: false,
  });
  assert.equal(h['Content-Security-Policy'], undefined);
  assert.equal(h['Strict-Transport-Security'], undefined);
  assert.equal(h['X-Content-Type-Options'], undefined);
  assert.equal(h['X-Frame-Options'], undefined);
  assert.equal(h['Cross-Origin-Embedder-Policy'], undefined);
  assert.equal(h['Referrer-Policy'], undefined);
});

// CSP

test('CSP: default policy is emitted with expected directives', () => {
  const h = headers();
  const csp = h['Content-Security-Policy'];
  assert.match(csp, /default-src 'self'/);
  assert.match(csp, /object-src 'none'/);
  assert.match(csp, /upgrade-insecure-requests/);
  assert.match(csp, /frame-ancestors 'self'/);
});

test('CSP: user directives merge over defaults', () => {
  const h = headers({
    contentSecurityPolicy: {
      directives: { scriptSrc: ["'self'", 'https://cdn.example.com'] },
    },
  });
  const csp = h['Content-Security-Policy'];
  assert.match(csp, /script-src 'self' https:\/\/cdn\.example\.com/);
  // Other defaults still present.
  assert.match(csp, /default-src 'self'/);
});

test('CSP: directive set to false is removed from output', () => {
  const h = headers({
    contentSecurityPolicy: { directives: { upgradeInsecureRequests: false } },
  });
  assert.doesNotMatch(h['Content-Security-Policy'], /upgrade-insecure-requests/);
});

test('CSP: useDefaults=false starts from empty', () => {
  const h = headers({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: { defaultSrc: ["'none'"] },
    },
  });
  assert.equal(h['Content-Security-Policy'], "default-src 'none'");
});

test('CSP: reportOnly flips the header name', () => {
  const h = headers({ contentSecurityPolicy: { reportOnly: true } });
  assert.ok(h['Content-Security-Policy-Report-Only']);
  assert.equal(h['Content-Security-Policy'], undefined);
});

test('CSP: rejects sources with header-delimiter characters', () => {
  assert.throws(() => headers({ contentSecurityPolicy: { directives: { scriptSrc: ['x; y'] } } }), SecurityError);
  assert.throws(() => headers({ contentSecurityPolicy: { directives: { scriptSrc: ['x, y'] } } }), SecurityError);
  assert.throws(() => headers({ contentSecurityPolicy: { directives: { scriptSrc: ['x\ny'] } } }), SecurityError);
});

test('CSP: rejects non-array directive values', () => {
  assert.throws(() => headers({ contentSecurityPolicy: { directives: { scriptSrc: "'self'" } } }), SecurityError);
});

// HSTS

test('HSTS: default is 180 days + includeSubDomains', () => {
  const h = headers();
  assert.match(h['Strict-Transport-Security'], /max-age=15552000; includeSubDomains/);
});

test('HSTS: preload requires 1y + includeSubDomains', () => {
  const h = headers({ hsts: { maxAge: 31_536_000, preload: true } });
  assert.match(h['Strict-Transport-Security'], /max-age=31536000; includeSubDomains; preload/);
});

test('HSTS: preload without 1y throws', () => {
  assert.throws(() => headers({ hsts: { maxAge: 1000, preload: true } }), SecurityError);
});

test('HSTS: preload without includeSubDomains throws', () => {
  assert.throws(
    () => headers({ hsts: { maxAge: 31_536_000, includeSubDomains: false, preload: true } }),
    SecurityError,
  );
});

test('HSTS: negative maxAge throws', () => {
  assert.throws(() => headers({ hsts: { maxAge: -1 } }), SecurityError);
});

// frameguard

test('frameguard: accepts DENY or SAMEORIGIN (case-insensitive)', () => {
  assert.equal(headers({ frameguard: 'sameorigin' })['X-Frame-Options'], 'SAMEORIGIN');
  assert.equal(headers({ frameguard: { action: 'DENY' } })['X-Frame-Options'], 'DENY');
});

test('frameguard: rejects ALLOW-FROM (deprecated)', () => {
  assert.throws(() => headers({ frameguard: 'ALLOW-FROM https://example.com' }), SecurityError);
});

// Permissions-Policy

test('permissionsPolicy: true emits a locked-down default', () => {
  const h = headers({ permissionsPolicy: true });
  assert.match(h['Permissions-Policy'], /camera=\(\)/);
  assert.match(h['Permissions-Policy'], /geolocation=\(\)/);
});

test('permissionsPolicy: custom features serialize with quoted origins', () => {
  const h = headers({
    permissionsPolicy: {
      features: {
        geolocation: ['self'],
        camera: ['https://example.com'],
        microphone: [],
      },
    },
  });
  const pp = h['Permissions-Policy'];
  assert.match(pp, /geolocation=\(self\)/);
  assert.match(pp, /camera=\("https:\/\/example\.com"\)/);
  assert.match(pp, /microphone=\(\)/);
});

test('permissionsPolicy: rejects non-array allowlist', () => {
  assert.throws(() => headers({ permissionsPolicy: { features: { camera: 'self' } } }), SecurityError);
});

// cspNonce

test('cspNonce: returns different values each call', () => {
  const a = cspNonce();
  const b = cspNonce();
  assert.notEqual(a, b);
});

test('cspNonce: default is 16 bytes base64 (~22 chars)', () => {
  const n = cspNonce();
  // base64 of 16 bytes is 24 chars with padding, 22 without. Buffer includes '='.
  assert.ok(n.length >= 22);
});

test('cspNonce: rejects sizes outside 8..64', () => {
  assert.throws(() => cspNonce(4), TypeError);
  assert.throws(() => cspNonce(128), TypeError);
  assert.throws(() => cspNonce(1.5), TypeError);
});

test('cspNonce: usable in a CSP directive', () => {
  const n = cspNonce();
  const h = headers({
    contentSecurityPolicy: {
      directives: { scriptSrc: ["'self'", `'nonce-${n}'`] },
    },
  });
  assert.ok(h['Content-Security-Policy'].includes(`'nonce-${n}'`));
});
