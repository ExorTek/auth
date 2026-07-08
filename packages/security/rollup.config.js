import { readFileSync } from 'node:fs';
import { createConfig } from '../../rollup.config.base.js';

const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8'));

export default createConfig(pkg, {
  entries: {
    index: 'src/index.js',
    csrf: 'src/csrf/index.js',
    'rate-limit': 'src/rate-limit/index.js',
    headers: 'src/headers/index.js',
    cors: 'src/cors/index.js',
    redirect: 'src/redirect/index.js',
    fastify: 'src/middleware/fastify.js',
    express: 'src/middleware/express.js',
    hono: 'src/middleware/hono.js',
    elysia: 'src/middleware/elysia.js',
  },
});
