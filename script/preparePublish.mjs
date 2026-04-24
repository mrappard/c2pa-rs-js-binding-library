import { copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const rootDir = new URL('..', import.meta.url).pathname;
const distDir = join(rootDir, 'dist');
const pkgDir = join(rootDir, 'pkg');

const wasmArtifacts = readdirSync(pkgDir).filter((file) => file.startsWith('c2pa_rs_wasm'));

if (!existsSync(distDir)) {
  throw new Error('dist directory does not exist. Run the build first.');
}

mkdirSync(distDir, { recursive: true });

for (const file of wasmArtifacts) {
  copyFileSync(join(pkgDir, file), join(distDir, file));
}

for (const file of ['index.js', 'index.d.ts']) {
  const filePath = join(distDir, file);
  const content = readFileSync(filePath, 'utf8')
    .replaceAll("../pkg/c2pa_rs_wasm.js", "./c2pa_rs_wasm.js");

  writeFileSync(filePath, content);
}

console.log(`Prepared dist/ for npm publish with ${wasmArtifacts.length} WASM artifact files.`);
