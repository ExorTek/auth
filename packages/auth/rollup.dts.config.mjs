/**
 * Declaration-bundling pass for the umbrella. Unlike the shared
 * `rollup.dts.config.mjs`, this one externalizes *every* bare specifier — not
 * just the bare package names in `dependencies`. Each entry's `.d.ts` is a lone
 * `export * from '@exortek/<pkg>[/subpath]'`; the shared config only lists bare
 * names as external, so the deep subpaths (`@exortek/jwt/token-pair`,
 * `@exortek/oauth2/providers/google`, …) were reported as "Unresolved
 * dependencies" — harmless (they stayed external, which is correct) but 90+
 * lines of noise. Matching the umbrella's own `rollup.config.js`, treat any
 * non-relative id as external so the pass is silent and the shim survives
 * verbatim for the consumer to resolve.
 */
import { readFileSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { dts } from 'rollup-plugin-dts';

const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8'));

// Derive entries from the `exports` map's `types` targets, exactly as the
// shared config does: './dist/jwt.d.ts' → 'jwt', './dist/oauth2/providers/
// google.d.ts' → 'oauth2/providers/google'.
const entries = [];
for (const condition of Object.values(pkg.exports)) {
  const target = condition && typeof condition === 'object' ? condition.types : undefined;
  if (typeof target !== 'string') continue;
  entries.push(target.replace(/^\.\/dist\//, '').replace(/\.d\.ts$/, ''));
}

const external = id => !id.startsWith('.') && !isAbsolute(id);

export default entries.map(name => ({
  input: `dist/${name}.d.ts`,
  output: { file: `dist/${name}.d.ts`, format: 'es' },
  external,
  plugins: [dts({ respectExternal: true })],
}));
