import { readFileSync } from 'node:fs';
import { createConfig } from '../../rollup.config.base.js';

const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8'));

export default createConfig(pkg, {
  entries: {
    index: 'src/index.js',
    generate: 'src/generate.js',
    import: 'src/import.js',
    export: 'src/export.js',
    thumbprint: 'src/thumbprint.js',
    validate: 'src/validate.js',
  },
});
