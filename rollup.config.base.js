import { nodeResolve } from '@rollup/plugin-node-resolve';
import { dts } from 'rollup-plugin-dts';

// Node libraries ship unminified so consumers can read node_modules,
// debug into stack traces with real names, and audit the tarball. Size
// matters less than legibility here — jose, jsonwebtoken, zod, drizzle
// all follow this convention.
const resolveOnce = nodeResolve();

export function createConfig(pkg, options = {}) {
  const external = [
    ...Object.keys(pkg.dependencies || {}),
    ...Object.keys(pkg.peerDependencies || {}),
    ...Object.keys(pkg.optionalDependencies || {}),
    /^node:/,
  ];
  const entries = options.entries || { index: 'src/index.js' };
  const plugins = [resolveOnce];

  return Object.entries(entries).flatMap(([name, input]) => [
    {
      input,
      output: { file: `dist/${name}.mjs`, format: 'esm', sourcemap: false },
      external,
      plugins,
    },
    {
      input,
      output: {
        file: `dist/${name}.cjs`,
        format: 'cjs',
        sourcemap: false,
        exports: 'named',
      },
      external,
      plugins,
    },
  ]);
}

/**
 * Second-pass config that flattens each entry's tsc-emitted `.d.ts` into a
 * single self-contained declaration file — inlining the `@exortek/shared`
 * types (which ship no `.d.ts` and are never published) so a consumer never
 * sees a dangling `import … from '@exortek/shared/*'` in the shipped types.
 *
 * `@exortek/shared` is mapped to its build-only emitted declarations
 * (`packages/shared/dist`, gitignored). Real runtime deps and `node:*` stay
 * external so consumers resolve them from their own install.
 *
 * Runs after `tsc` (which produces `dist/<entry>.d.ts`); the bundle overwrites
 * that same file in place.
 *
 * @param {object} pkg              The consuming package's package.json.
 * @param {Record<string, string>} entries  entry name → (unused) source path;
 *   only the keys matter — each names a `dist/<key>.d.ts` to flatten.
 */
export function createDtsConfig(pkg, entries) {
  const external = [
    ...Object.keys(pkg.dependencies || {}),
    ...Object.keys(pkg.peerDependencies || {}),
    ...Object.keys(pkg.optionalDependencies || {}),
    /^node:/,
  ];
  const plugin = dts({
    respectExternal: true,
    compilerOptions: {
      allowJs: true,
      checkJs: false,
      baseUrl: '.',
      // `@exortek/shared` is inlined at runtime by the bundler and ships no
      // `.d.ts`; point the declaration bundler at its build-only emit so the
      // types get inlined here too.
      paths: { '@exortek/shared/*': ['../shared/dist/*.d.ts'] },
    },
  });

  return Object.keys(entries).map(name => ({
    input: `dist/${name}.d.ts`,
    output: { file: `dist/${name}.d.ts`, format: 'es' },
    external,
    plugins: [plugin],
  }));
}
