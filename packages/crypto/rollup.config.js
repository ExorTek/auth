import { readFileSync } from 'node:fs';
import { createConfig } from '../../rollup.config.base.js';

const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8'));

export default createConfig(pkg, {
  entries: {
    index: 'src/index.js',
    hash: 'src/hash/index.js',
    cipher: 'src/cipher/index.js',
    sign: 'src/sign/index.js',
    binary: 'src/binary/index.js',
    encode: 'src/encode/index.js',
    random: 'src/random/index.js',
  },
});
