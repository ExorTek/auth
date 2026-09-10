import { readFileSync } from 'node:fs';
import { isAbsolute } from 'node:path';

// The umbrella is pure re-export glue: every entry file does nothing but
// `export * from '@exortek/<pkg>[/subpath]'`. So unlike the leaf packages
// (which bundle their own source via the shared `createConfig`), auth must
// treat *everything* as external — including deep subpaths like
// `@exortek/password/argon2`, whose lazy native binding is a dynamic import
// that rollup would otherwise try to inline into a multi-chunk output. Keeping
// them external emits a single-file `export * from` shim per entry, so the
// consumer resolves each real package from their own install.
const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8'));

const entries = {
  index: 'src/index.js',
};
// Every subpath in `exports` (except the root `.`) maps 1:1 to a src shim.
for (const [key, condition] of Object.entries(pkg.exports)) {
  if (key === '.') continue;
  const name = key.replace(/^\.\//, '');
  entries[name] = `src/${name}.js`;
}

const external = id => !id.startsWith('.') && !isAbsolute(id);

export default Object.entries(entries).flatMap(([name, input]) => [
  {
    input,
    output: { file: `dist/${name}.mjs`, format: 'esm', sourcemap: false },
    external,
  },
  {
    input,
    output: { file: `dist/${name}.cjs`, format: 'cjs', sourcemap: false, exports: 'named' },
    external,
  },
]);
