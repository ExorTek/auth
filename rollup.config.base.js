import { nodeResolve } from '@rollup/plugin-node-resolve';
import terser from '@rollup/plugin-terser';

const minify = terser({
  format: {
    comments: false,
    ecma: 2022,
  },
  compress: {
    ecma: 2022,
    passes: 2,
  },
  mangle: {
    keep_classnames: true,
    keep_fnames: /^[A-Z]|^assert|^is/, // classes + assertX + isX helpers stay readable
  },
});

export function createConfig(pkg, options = {}) {
  const external = [...Object.keys(pkg.dependencies || {}), ...Object.keys(pkg.peerDependencies || {}), /^node:/];

  const entries = options.entries || { index: 'src/index.js' };

  return Object.entries(entries).flatMap(([name, input]) => [
    {
      input,
      output: { file: `dist/${name}.mjs`, format: 'esm', sourcemap: true },
      external,
      plugins: [nodeResolve(), minify],
    },
    {
      input,
      output: {
        file: `dist/${name}.cjs`,
        format: 'cjs',
        sourcemap: true,
        exports: 'named',
      },
      external,
      plugins: [nodeResolve(), minify],
    },
  ]);
}
