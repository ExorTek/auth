import { test } from 'node:test';
import assert from 'node:assert/strict';
import { safeJsonParse, constantTimeEqual, parseCspReport, rateLimit, SecurityError } from '../src/index.js';

// safeJsonParse

test('safeJsonParse: parses ordinary JSON', () => {
  assert.deepEqual(safeJsonParse('{"a":1,"b":[2,3]}'), { a: 1, b: [2, 3] });
  assert.equal(safeJsonParse('"hi"'), 'hi');
  assert.equal(safeJsonParse('42'), 42);
  assert.equal(safeJsonParse('null'), null);
});

test('safeJsonParse: default reject drops payload with banned key', () => {
  assert.equal(safeJsonParse('{"__proto__":{"polluted":1}}'), null);
  assert.equal(safeJsonParse('{"constructor":{"prototype":{"x":1}}}'), null);
  assert.equal(safeJsonParse('{"nested":{"__proto__":1}}'), null);
});

test('safeJsonParse: strip mode returns object without the banned keys', () => {
  const out = safeJsonParse('{"a":1,"__proto__":{"x":2},"b":3}', { mode: 'strip' });
  assert.deepEqual(out, { a: 1, b: 3 });
  // Real Object.prototype is untouched.
  assert.equal({}.x, undefined);
});

test('safeJsonParse: throw mode raises SecurityError on banned key', () => {
  assert.throws(() => safeJsonParse('{"__proto__":1}', { mode: 'throw' }), SecurityError);
});

test('safeJsonParse: rejects oversized input before parsing', () => {
  assert.equal(safeJsonParse('"x"'.padStart(2000), { maxBytes: 100 }), null);
  assert.throws(() => safeJsonParse('"x"'.padStart(2000), { maxBytes: 100, mode: 'throw' }), SecurityError);
});

test('safeJsonParse: returns null on malformed JSON', () => {
  assert.equal(safeJsonParse('{not-json'), null);
  assert.equal(safeJsonParse(''), null);
  assert.equal(safeJsonParse(123), null);
});

test('safeJsonParse: accepts Buffer input', () => {
  const buf = Buffer.from('{"a":1}');
  assert.deepEqual(safeJsonParse(buf), { a: 1 });
});

test('safeJsonParse: enforces maxDepth', () => {
  let s = '"leaf"';
  for (let i = 0; i < 40; i++) {
    s = `[${s}]`;
  }
  assert.equal(safeJsonParse(s, { maxDepth: 10 }), null);
});

test('safeJsonParse: does not pollute Object.prototype even on banned input', () => {
  safeJsonParse('{"__proto__":{"pwned":1}}');
  safeJsonParse('{"__proto__":{"pwned":1}}', { mode: 'strip' });
  assert.equal({}.pwned, undefined);
});

// constantTimeEqual

test('constantTimeEqual: equal strings return true', () => {
  assert.equal(constantTimeEqual('abc', 'abc'), true);
  assert.equal(constantTimeEqual('', ''), true);
});

test('constantTimeEqual: unequal strings return false without throwing', () => {
  assert.equal(constantTimeEqual('abc', 'abd'), false);
  assert.equal(constantTimeEqual('abc', 'longer-string'), false); // length mismatch
});

test('constantTimeEqual: accepts Buffers and Uint8Arrays', () => {
  const a = Buffer.from([1, 2, 3]);
  const b = Buffer.from([1, 2, 3]);
  const c = new Uint8Array([1, 2, 3]);
  assert.equal(constantTimeEqual(a, b), true);
  assert.equal(constantTimeEqual(a, c), true);
});

test('constantTimeEqual: null/undefined return false safely', () => {
  assert.equal(constantTimeEqual(null, 'abc'), false);
  assert.equal(constantTimeEqual('abc', undefined), false);
  assert.equal(constantTimeEqual(null, null), false);
});

// parseCspReport

test('parseCspReport: parses legacy report-uri shape', () => {
  const body = JSON.stringify({
    'csp-report': {
      'document-uri': 'https://example.com/page',
      'referrer': '',
      'violated-directive': 'script-src',
      'effective-directive': 'script-src',
      'original-policy': "default-src 'self'",
      'blocked-uri': 'inline',
      'status-code': 200,
    },
  });
  const report = parseCspReport(body);
  assert.ok(report);
  assert.equal(report.documentUri, 'https://example.com/page');
  assert.equal(report.blockedUri, 'inline');
  assert.equal(report.effectiveDirective, 'script-src');
  assert.equal(report.statusCode, 200);
});

test('parseCspReport: parses modern report-to shape (array)', () => {
  const body = [
    {
      type: 'csp-violation',
      age: 0,
      url: 'https://example.com',
      body: {
        documentURL: 'https://example.com/page',
        blockedURL: 'https://evil.com/x.js',
        effectiveDirective: 'script-src-elem',
        disposition: 'enforce',
        sourceFile: 'https://example.com/main.js',
        lineNumber: 12,
        columnNumber: 3,
        sample: '<script>',
        statusCode: 200,
      },
    },
  ];
  const report = parseCspReport(body);
  assert.ok(report);
  assert.equal(report.documentUri, 'https://example.com/page');
  assert.equal(report.blockedUri, 'https://evil.com/x.js');
  assert.equal(report.effectiveDirective, 'script-src-elem');
  assert.equal(report.disposition, 'enforce');
  assert.equal(report.sourceFile, 'https://example.com/main.js');
  assert.equal(report.lineNumber, 12);
});

test('parseCspReport: accepts pre-parsed objects', () => {
  const obj = { 'csp-report': { 'blocked-uri': 'inline' } };
  assert.equal(parseCspReport(obj).blockedUri, 'inline');
});

test('parseCspReport: returns null for unrelated payloads', () => {
  assert.equal(parseCspReport('{}'), null);
  assert.equal(parseCspReport('not-json'), null);
  assert.equal(parseCspReport({ event: 'other' }), null);
  assert.equal(parseCspReport(null), null);
});

test('parseCspReport: report-to array skips non-CSP entries', () => {
  const body = [{ type: 'network-error', body: { foo: 1 } }];
  assert.equal(parseCspReport(body), null);
});

// rateLimit.withBan

test('rateLimit.withBan: allows under limit, bans after threshold denials', async () => {
  const store = rateLimit.stores.memory();
  const base = rateLimit.fixed({ requests: 1, window: '1m', store });
  const limiter = rateLimit.withBan(base, {
    store,
    threshold: 3,
    banDuration: '1h',
  });

  const results = [];
  for (let i = 0; i < 6; i++) {
    results.push(await limiter.check({ key: 'ip:1' }));
  }
  // 1st: allowed. 2nd-4th: denied via base. On 3rd denial (i=3, count=3),
  // ban is set. 5th+ requests: denied via ban.
  assert.equal(results[0].allowed, true);
  assert.equal(results[1].allowed, false);
  assert.equal(results[2].allowed, false);
  assert.equal(results[3].allowed, false);
  assert.equal(results[4].allowed, false);
  // The ban's retryAfter should reflect the ban duration (~3600s), NOT
  // the base window's remaining time.
  assert.ok(results[4].retryAfter > 100);
  store._stop();
});

test('rateLimit.withBan: unrelated key not affected', async () => {
  const store = rateLimit.stores.memory();
  const base = rateLimit.fixed({ requests: 1, window: '1m', store });
  const limiter = rateLimit.withBan(base, {
    store,
    threshold: 2,
    banDuration: '1h',
  });

  // Deliberately trigger threshold on ip:1.
  await limiter.check({ key: 'ip:1' });
  await limiter.check({ key: 'ip:1' });
  await limiter.check({ key: 'ip:1' });
  // ip:2 should still get its first allow.
  const other = await limiter.check({ key: 'ip:2' });
  assert.equal(other.allowed, true);
  store._stop();
});

test('rateLimit.withBan: rejects invalid config', () => {
  const store = rateLimit.stores.memory();
  const base = rateLimit.fixed({ requests: 1, window: '1m', store });
  assert.throws(() => rateLimit.withBan(null, { store, threshold: 1, banDuration: '1h' }), SecurityError);
  assert.throws(() => rateLimit.withBan(base, { threshold: 1, banDuration: '1h' }), SecurityError);
  assert.throws(() => rateLimit.withBan(base, { store, threshold: 0, banDuration: '1h' }), SecurityError);
  assert.throws(() => rateLimit.withBan(base, { store, threshold: 1, banDuration: 'bad' }), SecurityError);
  store._stop();
});
