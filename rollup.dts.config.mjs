/**
 * Declaration-bundling pass, shared by every package. Run from a package
 * directory *after* `tsc` has emitted per-file `.d.ts` into `dist/`:
 *
 *   rollup -c ../../rollup.dts.config.mjs
 *
 * It derives the entry list from the package's own `exports` map (each
 * subpath's `import` target names a `dist/<name>.d.ts`) and rewrites each
 * entry's declaration file in place as a self-contained bundle — see
 * `createDtsConfig` in `rollup.config.base.js`.
 */
import { readFileSync, existsSync } from 'node:fs';
import { createDtsConfig } from './rollup.config.base.js';

// The bundle inlines `@exortek/shared` types from its build-only emit. If that
// hasn't run, every entry would silently keep a dangling shared import — fail
// loudly instead. The root `yarn build` emits shared types first; a standalone
// package build needs `yarn workspace @exortek/shared build:types` beforehand.
if (!existsSync('../shared/dist')) {
  throw new Error(
    'rollup.dts.config: @exortek/shared declarations are missing — run `yarn workspace @exortek/shared build:types` first (the root `yarn build` does this automatically).',
  );
}

const pkg = JSON.parse(readFileSync('./package.json', 'utf8'));

/** @type {Record<string, string>} */
const entries = {};
for (const condition of Object.values(pkg.exports || {})) {
  // Derive from `types`, not `import`: tsc mirrors the source tree, so a
  // directory subpath (`src/stores/index.js`) emits `dist/stores/index.d.ts`
  // even though its bundled runtime output is the flat `dist/stores.mjs`. The
  // `types` field already points at the real declaration file.
  const target = condition && typeof condition === 'object' ? condition.types : undefined;
  if (typeof target !== 'string') {
    continue;
  }
  // './dist/index.d.ts' → 'index'; './dist/stores/index.d.ts' → 'stores/index'
  const name = target.replace(/^\.\/dist\//, '').replace(/\.d\.ts$/, '');
  entries[name] = name;
}

export default createDtsConfig(pkg, entries);
