import { readFileSync } from 'node:fs';
import { createConfig } from '../../rollup.config.base.js';

const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8'));

export default createConfig(pkg, {
  entries: {
    index: 'src/index.js',
    // The relying-party (SSO) client and the OpenID Provider each get their
    // own entry so an app that only logs users in never bundles the provider
    // half, and vice-versa. Framework adapters are split per framework so an
    // Express app never bundles the Fastify one.
    'client/index': 'src/client/index.js',
    'client/express': 'src/client/express.js',
    'client/fastify': 'src/client/fastify.js',
    'provider/index': 'src/provider/index.js',
    'provider/express': 'src/provider/express.js',
    'provider/fastify': 'src/provider/fastify.js',
  },
});
