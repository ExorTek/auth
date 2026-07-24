import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { parse, satisfies, isFrozenUA, clearCache } from '../src/index.js';

const chromeUA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36';
const mobileUA =
  'Mozilla/5.0 (Linux; Android 14; SM-S911B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.71 Mobile Safari/537.36';
const firefoxUA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0';

describe('satisfies()', () => {
  it('>= operator', () => {
    const r = parse(chromeUA);
    assert.equal(satisfies(r, { chrome: '>=120' }), true);
    assert.equal(satisfies(r, { chrome: '>=200' }), false);
  });

  it('> operator', () => {
    const r = parse(chromeUA);
    assert.equal(satisfies(r, { chrome: '>100' }), true);
    assert.equal(satisfies(r, { chrome: '>126' }), false);
  });

  it('<= operator', () => {
    const r = parse(chromeUA);
    assert.equal(satisfies(r, { chrome: '<=126' }), true);
    assert.equal(satisfies(r, { chrome: '<=100' }), false);
  });

  it('< operator', () => {
    const r = parse(chromeUA);
    assert.equal(satisfies(r, { chrome: '<200' }), true);
    assert.equal(satisfies(r, { chrome: '<126' }), false);
  });

  it('= operator', () => {
    const r = parse(chromeUA);
    assert.equal(satisfies(r, { chrome: '=126' }), true);
    assert.equal(satisfies(r, { chrome: '=100' }), false);
  });

  it('!= operator', () => {
    const r = parse(chromeUA);
    assert.equal(satisfies(r, { chrome: '!=100' }), true);
    assert.equal(satisfies(r, { chrome: '!=126' }), false);
  });

  it('OR logic across browsers', () => {
    const r = parse(chromeUA);
    assert.equal(satisfies(r, { firefox: '>=100', chrome: '>=120' }), true);
    assert.equal(satisfies(r, { firefox: '>=100', safari: '>=16' }), false);
  });

  it('browser aliases — chrome matches Mobile Chrome', () => {
    const r = parse(mobileUA);
    assert.equal(satisfies(r, { chrome: '>=120' }), true);
  });

  it('device-scoped conditions', () => {
    const r = parse(mobileUA);
    assert.equal(satisfies(r, { mobile: { chrome: '>=120' } }), true);
    assert.equal(satisfies(r, { desktop: { chrome: '>=120' } }), false);
  });

  it('desktop fallback — no device type means desktop', () => {
    const r = parse(chromeUA);
    assert.equal(satisfies(r, { desktop: { chrome: '>=120' } }), true);
    assert.equal(satisfies(r, { mobile: { chrome: '>=120' } }), false);
  });

  it('returns false for no browser name', () => {
    const r = parse('totally-unknown/1.0');
    assert.equal(satisfies(r, { chrome: '>=1' }), false);
  });

  it('returns false for invalid condition', () => {
    const r = parse(chromeUA);
    assert.equal(satisfies(r, { chrome: 'abc' }), false);
  });
});

describe('isFrozenUA()', () => {
  it('detects frozen Chrome UA', () => {
    const frozen =
      'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36';
    assert.equal(isFrozenUA(frozen), true);
  });

  it('returns false for non-frozen UA', () => {
    assert.equal(isFrozenUA(mobileUA), false);
  });

  it('returns false for non-Chrome UA', () => {
    assert.equal(isFrozenUA(firefoxUA), false);
  });

  it('returns false for non-string input', () => {
    assert.equal(isFrozenUA(null), false);
    assert.equal(isFrozenUA(123), false);
  });
});

describe('clearCache()', () => {
  it('does not throw', () => {
    assert.doesNotThrow(() => clearCache());
  });
});

describe('__proto__ Client Hints safety', () => {
  it('does not crash with __proto__ brand', () => {
    const r = parse(chromeUA, {
      headers: {
        'sec-ch-ua': '"__proto__";v="1", "Chromium";v="126"',
        'user-agent': chromeUA,
      },
    });
    assert.doesNotThrow(() => {
      if (r.browser.name) {
        r.browser.name.toLowerCase();
      }
    });
    assert.notEqual(r.browser.name, Object.prototype);
  });
});
