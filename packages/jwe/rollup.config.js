import { readFileSync } from 'node:fs';
import { createConfig } from '../../rollup.config.base.js';

const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8'));

export default createConfig(pkg, {
  entries: {
    index: 'src/index.js',
    encrypt: 'src/encrypt.js',
    decrypt: 'src/decrypt.js',
    decode: 'src/decode.js',
    json: 'src/json.js',
  },
});
