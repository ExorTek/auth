import { readFileSync } from 'node:fs';
import { createConfig } from '../../rollup.config.base.js';

const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8'));

export default createConfig(pkg, {
  entries: {
    index: 'src/index.js',
    // The relying-party (SSO) client and the OpenID Provider each get their
    // own entry so an app that only logs users in never bundles the provider
    // half, and vice-versa.
    'client/index': 'src/client/index.js',
    'provider/index': 'src/provider/index.js',
  },
});
