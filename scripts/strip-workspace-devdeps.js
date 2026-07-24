#!/usr/bin/env node
/**
 * Remove workspace-only devDependencies from package.json before publish
 * so `"@exortek/shared": "0.0.0"` doesn't leak onto the npm registry.
 *
 * Run with --restore to put them back after publish.
 *
 * Usage (in release pipeline):
 *   node scripts/strip-workspace-devdeps.js
 *   yarn workspaces foreach ... npm publish ...
 *   node scripts/strip-workspace-devdeps.js --restore
 */

import { readFileSync, writeFileSync, existsSync, unlinkSync, copyFileSync } from 'node:fs';
import { join } from 'node:path';
import { readdirSync } from 'node:fs';

const STRIP_PATTERN = /^@exortek\//;
const PACKAGES_DIR = join(import.meta.dirname, '..', 'packages');

const restore = process.argv.includes('--restore');
const dirs = readdirSync(PACKAGES_DIR, { withFileTypes: true })
  .filter(d => d.isDirectory())
  .map(d => d.name);

let count = 0;

for (const dir of dirs) {
  const pkgPath = join(PACKAGES_DIR, dir, 'package.json');
  const bakPath = pkgPath + '.prepublish';
  if (!existsSync(pkgPath)) continue;

  if (restore) {
    if (!existsSync(bakPath)) continue;
    copyFileSync(bakPath, pkgPath);
    unlinkSync(bakPath);
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
    count++;
    console.log(`  restored: ${pkg.name}`);
    continue;
  }

  const raw = readFileSync(pkgPath, 'utf8');
  const pkg = JSON.parse(raw);
  const devDeps = pkg.devDependencies;
  if (!devDeps) continue;

  const toStrip = Object.keys(devDeps).filter(name => STRIP_PATTERN.test(name));
  if (toStrip.length === 0) continue;

  copyFileSync(pkgPath, bakPath);

  for (const name of toStrip) {
    delete devDeps[name];
  }
  if (Object.keys(devDeps).length === 0) {
    delete pkg.devDependencies;
  }
  writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + '\n');
  count++;
  console.log(`  stripped: ${pkg.name} (${toStrip.join(', ')})`);
}

console.log(`\n${restore ? 'restored' : 'stripped'} ${count} package(s)`);
