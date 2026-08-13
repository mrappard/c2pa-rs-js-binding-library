import { copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const rootDir = new URL('..', import.meta.url).pathname;
const distDir = join(rootDir, 'dist');
const distNodeDir = join(rootDir, 'dist-node');
const pkgDir = join(rootDir, 'pkg');
const pkgNodeDir = join(rootDir, 'pkg-node');

if (!existsSync(distDir)) {
  throw new Error('dist directory does not exist. Run build:ts first.');
}
if (!existsSync(distNodeDir)) {
  throw new Error('dist-node directory does not exist. Run build:ts:node first.');
}
if (!existsSync(pkgNodeDir)) {
  throw new Error('pkg-node directory does not exist. Run build:wasm:node first.');
}

mkdirSync(distDir, { recursive: true });
mkdirSync(distNodeDir, { recursive: true });

// ── bundler dist (for Vite / webpack consumers) ──
const wasmArtifacts = readdirSync(pkgDir).filter((file) => file.startsWith('c2pa_rs_wasm'));
for (const file of wasmArtifacts) {
  copyFileSync(join(pkgDir, file), join(distDir, file));
}

for (const file of ['index.js', 'index.d.ts']) {
  const filePath = join(distDir, file);
  const content = readFileSync(filePath, 'utf8')
    .replaceAll('../pkg/c2pa_rs_wasm.js', './c2pa_rs_wasm.js');
  writeFileSync(filePath, content);
}

console.log(`Prepared dist/ for npm publish with ${wasmArtifacts.length} WASM artifact files.`);

// ── Node.js dist (CJS — for plain Node consumers) ──
const nodeWasmArtifacts = readdirSync(pkgNodeDir).filter((file) => file.startsWith('c2pa_rs_wasm'));
for (const file of nodeWasmArtifacts) {
  copyFileSync(join(pkgNodeDir, file), join(distNodeDir, file));
}

// Rewrite require() paths in the CJS-compiled TS output
for (const file of ['index.js', 'index.d.ts']) {
  const filePath = join(distNodeDir, file);
  const content = readFileSync(filePath, 'utf8')
    .replaceAll('../pkg/c2pa_rs_wasm.js', './c2pa_rs_wasm.js');
  writeFileSync(filePath, content);
}

// Mark this directory as CommonJS so Node doesn't try to parse it as ESM
writeFileSync(join(distNodeDir, 'package.json'), JSON.stringify({ type: 'commonjs' }, null, 2) + '\n');

console.log(`Prepared dist-node/ for npm publish with ${nodeWasmArtifacts.length} WASM artifact files.`);
