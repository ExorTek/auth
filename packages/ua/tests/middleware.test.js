import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { uaMiddleware } from '../src/middleware/express.js';
import { botGuard } from '../src/middleware/bot-guard-express.js';

function mockReq(ua, headers) {
  return { headers: { 'user-agent': ua, ...headers } };
}

function mockRes() {
  const res = {
    _headers: {},
    _status: null,
    _body: null,
    setHeader(k, v) {
      res._headers[k] = v;
    },
    appendHeader(k, v) {
      res._headers[k] = res._headers[k] ? res._headers[k] + ', ' + v : v;
    },
    writeHead(status, headers) {
      res._status = status;
      Object.assign(res._headers, headers);
    },
    end(body) {
      res._body = body;
    },
  };
  return res;
}

const chromeUA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36';
const googlebotUA = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
const gptbotUA =
  'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)';

describe('Express UA middleware', () => {
  it('attaches parsed result to req.ua', () => {
    const mw = uaMiddleware();
    const req = mockReq(chromeUA);
    const res = mockRes();
    let called = false;
    mw(req, res, () => {
      called = true;
    });
    assert.ok(called);
    assert.equal(req.ua.browser.name, 'Chrome');
    assert.equal(req.ua.os.name, 'Windows');
  });

  it('sets Accept-CH and Vary response headers', () => {
    const mw = uaMiddleware();
    const req = mockReq(chromeUA);
    const res = mockRes();
    mw(req, res, () => {});
    assert.ok(res._headers['Accept-CH']);
    assert.ok(res._headers['Vary']);
  });

  it('detects bots and attaches .bot field', () => {
    const mw = uaMiddleware();
    const req = mockReq(googlebotUA);
    const res = mockRes();
    mw(req, res, () => {});
    assert.ok(req.ua.bot);
    assert.equal(req.ua.bot.name, 'Googlebot');
    assert.equal(req.ua.bot.category, 'search');
  });

  it('does not mutate cached parse result', () => {
    const mw = uaMiddleware();
    const req1 = mockReq(chromeUA);
    const res1 = mockRes();
    mw(req1, res1, () => {});
    const req2 = mockReq(chromeUA);
    const res2 = mockRes();
    mw(req2, res2, () => {});
    assert.notStrictEqual(req1.ua, req2.ua);
  });

  it('fires onUnknown for unrecognized UA', () => {
    let captured = null;
    const mw = uaMiddleware({
      onUnknown(ua) {
        captured = ua;
      },
    });
    const req = mockReq('totally-unknown-agent/1.0');
    const res = mockRes();
    mw(req, res, () => {});
    assert.equal(captured, 'totally-unknown-agent/1.0');
  });

  it('fires onBot and blocks when returning true', () => {
    let captured = null;
    const mw = uaMiddleware({
      onBot(bot) {
        captured = bot;
        return true;
      },
    });
    const req = mockReq(googlebotUA);
    const res = mockRes();
    let nextCalled = false;
    mw(req, res, () => {
      nextCalled = true;
    });
    assert.ok(captured);
    assert.equal(captured.name, 'Googlebot');
    assert.equal(res._status, 403);
    assert.equal(nextCalled, false);
  });

  it('fires onBot but allows when returning undefined', () => {
    let captured = null;
    const mw = uaMiddleware({
      onBot(bot) {
        captured = bot;
      },
    });
    const req = mockReq(googlebotUA);
    const res = mockRes();
    let nextCalled = false;
    mw(req, res, () => {
      nextCalled = true;
    });
    assert.ok(captured);
    assert.ok(nextCalled);
  });

  it('fires onParsed after parse + bot detection', () => {
    let captured = null;
    const mw = uaMiddleware({
      onParsed(result) {
        captured = result;
      },
    });
    const req = mockReq(chromeUA);
    const res = mockRes();
    mw(req, res, () => {});
    assert.ok(captured);
    assert.equal(captured.browser.name, 'Chrome');
  });
});

describe('Express bot guard middleware', () => {
  it('allows non-bot requests through', () => {
    const mw = botGuard({ deny: ['ai-training'] });
    const req = mockReq(chromeUA);
    const res = mockRes();
    let nextCalled = false;
    mw(req, res, () => {
      nextCalled = true;
    });
    assert.ok(nextCalled);
  });

  it('blocks denied bot categories', () => {
    const mw = botGuard({ deny: ['ai-training'] });
    const req = mockReq(gptbotUA);
    const res = mockRes();
    let nextCalled = false;
    mw(req, res, () => {
      nextCalled = true;
    });
    assert.equal(res._status, 403);
    assert.equal(nextCalled, false);
  });

  it('allows bots not in deny list', () => {
    const mw = botGuard({ deny: ['ai-training'] });
    const req = mockReq(googlebotUA);
    const res = mockRes();
    let nextCalled = false;
    mw(req, res, () => {
      nextCalled = true;
    });
    assert.ok(nextCalled);
  });

  it('denyAll blocks all bots', () => {
    const mw = botGuard({ denyAll: true });
    const req = mockReq(googlebotUA);
    const res = mockRes();
    let nextCalled = false;
    mw(req, res, () => {
      nextCalled = true;
    });
    assert.equal(res._status, 403);
    assert.equal(nextCalled, false);
  });

  it('allow overrides denyAll', () => {
    const mw = botGuard({ denyAll: true, allow: ['search'] });
    const req = mockReq(googlebotUA);
    const res = mockRes();
    let nextCalled = false;
    mw(req, res, () => {
      nextCalled = true;
    });
    assert.ok(nextCalled);
  });

  it('fires onBlocked callback', () => {
    let captured = null;
    const mw = botGuard({
      deny: ['ai-training'],
      onBlocked(bot) {
        captured = bot;
      },
    });
    const req = mockReq(gptbotUA);
    const res = mockRes();
    mw(req, res, () => {});
    assert.ok(captured);
    assert.equal(captured.name, 'GPTBot');
  });

  it('fires onAllowed callback', () => {
    let captured = null;
    const mw = botGuard({
      deny: ['ai-training'],
      onAllowed(bot) {
        captured = bot;
      },
    });
    const req = mockReq(googlebotUA);
    const res = mockRes();
    mw(req, res, () => {});
    assert.ok(captured);
    assert.equal(captured.name, 'Googlebot');
  });

  it('uses custom status code', () => {
    const mw = botGuard({ deny: ['search'], status: 429 });
    const req = mockReq(googlebotUA);
    const res = mockRes();
    mw(req, res, () => {});
    assert.equal(res._status, 429);
  });
});
