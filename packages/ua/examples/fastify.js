import Fastify from 'fastify';
import { uaPlugin } from '@exortek/ua/middleware/fastify';

const app = Fastify();

await app.register(uaPlugin, {
  clientHints: true,
  sendAcceptCH: true,
  detectBots: true,
  onUnknown(ua) {
    console.warn('Unrecognized UA:', ua.substring(0, 100));
  },
});

app.get('/api/info', async request => {
  return {
    browser: request.ua.browser.name,
    version: request.ua.browser.major,
    os: request.ua.os.name,
    device: request.ua.device.type || 'desktop',
    bot: request.ua.bot?.name || null,
    confidence: request.ua.bot?.confidence || null,
  };
});

app.get('/api/data', async (request, reply) => {
  if (request.ua.bot) {
    reply.code(403);
    return { error: 'Bot access not allowed' };
  }

  return { data: 'sensitive content' };
});

await app.listen({ port: 3000 });
