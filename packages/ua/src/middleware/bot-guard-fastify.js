import { fastifyPlugin } from '@exortek/shared/fastify-plugin';
import { detectBot } from '../bots.js';

/**
 * @typedef {Object} BotGuardPluginOptions
 * @property {string[]} [allow] — categories to always allow (overrides deny)
 * @property {string[]} [deny] — categories to block
 * @property {boolean} [denyAll=false] — block all detected bots
 * @property {number} [status=403] — HTTP status for blocked requests
 * @property {(bot: import('../bots.js').BotInfo, req: unknown) => unknown} [onBlocked]
 * @property {(bot: import('../bots.js').BotInfo, req: unknown) => void} [onAllowed]
 */

/**
 * Fastify plugin that blocks bots by category.
 *
 *   import { botGuardPlugin } from '@exortek/ua/middleware/bot-guard/fastify';
 *
 *   await app.register(botGuardPlugin, {
 *     deny: ['ai-training', 'seo'],
 *     onBlocked(bot, req) {
 *       console.log(`Blocked ${bot.name}`);
 *     },
 *   });
 *
 * @param {import('fastify').FastifyInstance} fastify
 * @param {BotGuardPluginOptions} options
 */
export const botGuardPlugin = fastifyPlugin(
  async function botGuardPluginFn(fastify, options) {
    const opts = {
      status: 403,
      ...options,
    };

    const allowSet = opts.allow ? new Set(opts.allow) : null;
    const denySet = opts.deny ? new Set(opts.deny) : null;

    fastify.addHook('onRequest', async (request, reply) => {
      const ua = request.headers['user-agent'] || '';
      const bot = detectBot(ua);

      if (!bot) {
        return;
      }

      const blocked = opts.denyAll
        ? !allowSet?.has(bot.category)
        : denySet?.has(bot.category) && !allowSet?.has(bot.category);

      if (blocked) {
        if (opts.onBlocked) {
          opts.onBlocked(bot, request);
        }
        reply.code(opts.status).send({ error: 'bot_denied', category: bot.category });
        return;
      }

      if (opts.onAllowed) {
        opts.onAllowed(bot, request);
      }
    });
  },
  { name: '@exortek/ua/bot-guard' },
);

export default botGuardPlugin;
