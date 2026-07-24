import { readFileSync } from 'node:fs';
import { createConfig } from '../../rollup.config.base.js';

const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8'));

export default createConfig(pkg, {
  entries: {
    index: 'src/index.js',
    bots: 'src/bots.js',
    fingerprint: 'src/fingerprint.js',
    'middleware/express': 'src/middleware/express.js',
    'middleware/fastify': 'src/middleware/fastify.js',
    'middleware/bot-guard-express': 'src/middleware/bot-guard-express.js',
    'middleware/bot-guard-fastify': 'src/middleware/bot-guard-fastify.js',
  },
});
