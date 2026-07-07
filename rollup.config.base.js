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
    module: true,
    toplevel: true,
    unsafe_arrows: true,
    pure_getters: true,
  },
  mangle: {
    keep_classnames: true,
    keep_fnames: /^[A-Z]|^assert|^is/, // classes + assertX + isX helpers stay readable
  },
});

const resolveOnce = nodeResolve();
const minifyOnce = minify;

export function createConfig(pkg, options = {}) {
  const external = [...Object.keys(pkg.dependencies || {}), ...Object.keys(pkg.peerDependencies || {}), /^node:/];
  const entries = options.entries || { index: 'src/index.js' };
  const plugins = [resolveOnce, minifyOnce];

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
