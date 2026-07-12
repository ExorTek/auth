import { readFileSync } from 'node:fs';
import { createConfig } from '../../rollup.config.base.js';

const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8'));

export default createConfig(pkg, {
  entries: {
    index: 'src/index.js',
    totp: 'src/totp.js',
    hotp: 'src/hotp.js',
    backup: 'src/backup.js',
    uri: 'src/uri.js',
    enroll: 'src/enroll.js',
  },
});
