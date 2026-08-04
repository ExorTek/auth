import { readFileSync } from 'node:fs';
import { createConfig } from '../../rollup.config.base.js';

const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8'));

const providers = [
  'google',
  'github',
  'microsoft',
  'discord',
  'facebook',
  'linkedin',
  'spotify',
  'twitch',
  'apple',
  'twitter',
  'okta',
  'azure',
];

export default createConfig(pkg, {
  entries: {
    index: 'src/index.js',
    // The authorization server (Phase 2) — its own entry so RP-only
    // consumers never bundle it.
    'server/index': 'src/server/index.js',
    'server/express': 'src/server/middleware/express.js',
    'server/fastify': 'src/server/middleware/fastify.js',
    // One entry per provider so a consumer bundles only what they import.
    ...Object.fromEntries(providers.map(name => [`providers/${name}`, `src/providers/${name}.js`])),
  },
});
