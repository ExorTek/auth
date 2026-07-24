import { fastifyPlugin } from '@exortek/shared/fastify-plugin';
import { parse, ACCEPT_CH, VARY_CH } from '../index.js';
import { detectBot } from '../bots.js';

/**
 * @typedef {Object} UAPluginOptions
 * @property {boolean} [clientHints=true]
 * @property {boolean} [sendAcceptCH=true]
 * @property {boolean} [detectBots=true]
 * @property {string} [property='ua']
 * @property {(ua: string) => void} [onUnknown]
 * @property {(bot: import('../bots.js').BotInfo, req: unknown) => boolean|void} [onBot]
 * @property {(result: object, req: unknown) => void} [onParsed]
 */

/**
 * Fastify plugin that parses the User-Agent and attaches
 * the result to `request.ua` (configurable via `options.property`).
 *
 *   import { uaPlugin } from '@exortek/ua/middleware/fastify';
 *
 *   await app.register(uaPlugin, { detectBots: true });
 *
 *   app.get('/', async (request) => {
 *     console.log(request.ua.browser.name); // 'Chrome'
 *     console.log(request.ua.bot);          // null or { name, type, category }
 *   });
 *
 * @param {import('fastify').FastifyInstance} fastify
 * @param {UAPluginOptions} options
 */
export const uaPlugin = fastifyPlugin(
  async function uaPluginFn(fastify, options) {
    const opts = {
      clientHints: true,
      sendAcceptCH: true,
      detectBots: true,
      property: 'ua',
      ...options,
    };

    fastify.decorateRequest(opts.property, null);

    if (opts.sendAcceptCH && opts.clientHints) {
      fastify.addHook('onSend', async (_req, reply, payload) => {
        if (!reply.hasHeader('Accept-CH')) {
          reply.header('Accept-CH', ACCEPT_CH);
          reply.header('Vary', VARY_CH);
        }
        return payload;
      });
    }

    fastify.addHook('onRequest', async (request, reply) => {
      const ua = request.headers['user-agent'] || '';
      const parsed = parse(ua, {
        headers: opts.clientHints ? request.headers : undefined,
        clientHints: opts.clientHints,
      });

      const bot = opts.detectBots ? detectBot(ua) : null;
      const result = { ...parsed, bot };

      if (bot && opts.onBot) {
        if (opts.onBot(bot, request) === true) {
          reply.code(403).send({ error: 'bot_denied', category: bot.category });
          return;
        }
      }

      if (opts.onUnknown && !result.browser.name && !bot) {
        opts.onUnknown(ua);
      }

      if (opts.onParsed) {
        opts.onParsed(result, request);
      }

      request[opts.property] = result;
    });
  },
  { name: '@exortek/ua' },
);

export default uaPlugin;
