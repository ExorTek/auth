import { readFileSync } from 'node:fs';
import { createConfig } from '../../rollup.config.base.js';

const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8'));

export default createConfig(pkg, {
  entries: {
    index: 'src/index.js',
    scrypt: 'src/algorithms/scrypt.js',
    pbkdf2: 'src/algorithms/pbkdf2.js',
    argon2: 'src/algorithms/argon2.js',
    bcrypt: 'src/algorithms/bcrypt.js',
    strength: 'src/strength.js',
    generate: 'src/generate.js',
    policy: 'src/policy.js',
    hibp: 'src/hibp.js',
  },
});
