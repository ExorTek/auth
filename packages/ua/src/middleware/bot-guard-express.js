import { detectBot } from '../bots.js';

/**
 * @typedef {Object} BotGuardOptions
 * @property {string[]} [allow] — categories to always allow (overrides deny)
 * @property {string[]} [deny] — categories to block
 * @property {boolean} [denyAll=false] — block all detected bots
 * @property {number} [status=403] — HTTP status for blocked requests
 * @property {(bot: import('../bots.js').BotInfo, req: unknown) => unknown} [onBlocked]
 * @property {(bot: import('../bots.js').BotInfo, req: unknown) => void} [onAllowed]
 */

/**
 * Express middleware that blocks bots by category.
 *
 *   import { botGuard } from '@exortek/ua/middleware/bot-guard';
 *
 *   // Block AI training crawlers
 *   app.use(botGuard({ deny: ['ai-training'] }));
 *
 *   // Block everything except search engines
 *   app.use(botGuard({ denyAll: true, allow: ['search'] }));
 *
 *   // Custom blocking logic
 *   app.use(botGuard({
 *     deny: ['ai-training', 'seo'],
 *     onBlocked(bot, req) {
 *       console.log(`Blocked ${bot.name} (${bot.category})`);
 *     },
 *   }));
 *
 * @param {BotGuardOptions} [options]
 * @returns {Function}
 */
export function botGuard(options) {
  const opts = {
    status: 403,
    ...options,
  };

  const allowSet = opts.allow ? new Set(opts.allow) : null;
  const denySet = opts.deny ? new Set(opts.deny) : null;

  return function botGuardMiddleware(req, res, next) {
    const ua = req.headers['user-agent'] || '';
    const bot = detectBot(ua);

    if (!bot) {
      next();
      return;
    }

    const blocked = opts.denyAll
      ? !allowSet?.has(bot.category)
      : denySet?.has(bot.category) && !allowSet?.has(bot.category);

    if (blocked) {
      if (opts.onBlocked) {
        opts.onBlocked(bot, req);
      }
      res.writeHead(opts.status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'bot_denied', category: bot.category }));
      return;
    }

    if (opts.onAllowed) {
      opts.onAllowed(bot, req);
    }
    next();
  };
}
