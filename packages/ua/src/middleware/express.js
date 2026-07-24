import { parse, ACCEPT_CH, VARY_CH } from '../index.js';
import { detectBot } from '../bots.js';

/**
 * @typedef {Object} UAMiddlewareOptions
 * @property {boolean} [clientHints=true]
 * @property {boolean} [sendAcceptCH=true]
 * @property {boolean} [detectBots=true]
 * @property {string} [property='ua']
 * @property {(ua: string) => void} [onUnknown]
 * @property {(bot: import('../bots.js').BotInfo, req: unknown) => boolean|void} [onBot]
 * @property {(result: object, req: unknown) => void} [onParsed]
 */

/**
 * Express middleware that parses the User-Agent and attaches
 * the result to `req.ua` (configurable via `options.property`).
 *
 *   import { uaMiddleware } from '@exortek/ua/middleware/express';
 *
 *   // Route-level (recommended)
 *   app.get('/', uaMiddleware(), (req, res) => {
 *     console.log(req.ua.browser.name); // 'Chrome'
 *     console.log(req.ua.bot);          // null or { name, type, category }
 *   });
 *
 *   // Or global
 *   app.use(uaMiddleware());
 *
 * @param {UAMiddlewareOptions} [options]
 * @returns {Function}
 */
export function uaMiddleware(options) {
  const opts = {
    clientHints: true,
    sendAcceptCH: true,
    detectBots: true,
    property: 'ua',
    ...options,
  };

  return function uaParser(req, res, next) {
    if (opts.sendAcceptCH && opts.clientHints) {
      res.setHeader('Accept-CH', ACCEPT_CH);
      if (res.appendHeader) {
        res.appendHeader('Vary', VARY_CH);
      } else {
        res.setHeader('Vary', VARY_CH);
      }
    }

    const ua = req.headers['user-agent'] || '';
    const parsed = parse(ua, {
      headers: opts.clientHints ? req.headers : undefined,
      clientHints: opts.clientHints,
    });

    const bot = opts.detectBots ? detectBot(ua) : null;
    const result = { ...parsed, bot };

    if (bot && opts.onBot) {
      if (opts.onBot(bot, req) === true) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'bot_denied', category: bot.category }));
        return;
      }
    }

    if (opts.onUnknown && !result.browser.name && !bot) {
      opts.onUnknown(ua);
    }

    if (opts.onParsed) {
      opts.onParsed(result, req);
    }

    req[opts.property] = result;
    next();
  };
}
