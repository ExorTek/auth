import { nodeResolve } from '@rollup/plugin-node-resolve';

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
