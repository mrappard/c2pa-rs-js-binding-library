import { extractManifestToSidecar, verifyAsset, verifyManifestBytes } from '../src/index.ts';
import { readFileSync, writeFileSync, mkdirSync } from 'fs';
import { join, dirname, resolve, extname, basename } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = resolve(__dirname, '..');

type Environment = {
  /** Path to the asset with an embedded C2PA manifest (relative to project root or absolute). */
  inputFile: string;
  /** MIME type of the asset, e.g. "image/jpeg", "image/png", "application/pdf". */
  format: string;
  /**
   * Where to write the extracted sidecar (.c2pa) file.
   * Defaults to script/output/<filename>.c2pa
   */
  outputSidecar?: string;
  /**
   * Where to write the stripped asset (original file with the embedded manifest removed).
   * Omit or set to "" to skip writing the stripped asset.
   */
  outputStrippedAsset?: string;
  /**
   * Optional manifest ID (e.g. "urn:c2pa:828b19c8-...") to target a specific manifest in the
   * store. If set, the script validates the ID exists and prints its metadata before writing.
   * If omitted or "", the active manifest is used. Run once without this set to discover IDs.
   */
  manifestId?: string;
};

const env: Environment = JSON.parse(
  readFileSync(join(__dirname, 'environment.json'), 'utf-8')
).extractSidecar;

const inputPath = resolve(root, env.inputFile);
const stem = basename(env.inputFile, extname(env.inputFile));

const sidecarPath = env.outputSidecar
  ? resolve(root, env.outputSidecar)
  : join(__dirname, 'output', `${stem}.c2pa`);

const strippedPath = env.outputStrippedAsset
  ? resolve(root, env.outputStrippedAsset)
  : null;

async function run() {
  console.log(`Input:          ${inputPath}`);
  console.log(`Format:         ${env.format}`);
  console.log(`Sidecar output: ${sidecarPath}`);
  if (strippedPath) console.log(`Stripped asset: ${strippedPath}`);
  console.log('');

  const asset = new Uint8Array(readFileSync(inputPath));

  // Read manifest IDs from the original embedded asset.
  const outcome = await verifyAsset(env.format as any, asset, []);
  console.log('DEBUG verifyAsset outcome:', JSON.stringify(outcome, null, 2));
  const store = outcome.manifestStore;
  const allIds = store ? Object.keys(store.manifests) : [];
  const activeId = store?.activeManifest ?? null;

  if (allIds.length === 0) {
    console.error('No manifests found in the asset.');
    process.exit(1);
  }

  if (env.manifestId) {
    if (!allIds.includes(env.manifestId)) {
      console.error(`Manifest ID not found: ${env.manifestId}`);
      console.error(`Available IDs:\n  ${allIds.join('\n  ')}`);
      process.exit(1);
    }
    const m = store!.manifests[env.manifestId];
    console.log(`Manifest:`);
    console.log(`  ID:        ${env.manifestId}${env.manifestId === activeId ? ' (active)' : ''}`);
    if (m.title)          console.log(`  Title:     ${m.title}`);
    if (m.claimGenerator) console.log(`  Generator: ${m.claimGenerator}`);
  } else {
    console.log(`Active manifest: ${activeId}`);
    if (allIds.length > 1) {
      console.log(`All IDs in store:`);
      allIds.forEach((id) => console.log(`  ${id}${id === activeId ? ' (active)' : ''}`));
    }
  }

  console.log('');

  const result = extractManifestToSidecar(env.format as any, asset);

  mkdirSync(dirname(sidecarPath), { recursive: true });
  writeFileSync(sidecarPath, result.manifest);
  console.log(`Sidecar written: ${sidecarPath} (${result.manifest.length} bytes)`);

  if (strippedPath) {
    mkdirSync(dirname(strippedPath), { recursive: true });
    writeFileSync(strippedPath, result.signedAsset);
    console.log(`Stripped asset written: ${strippedPath} (${result.signedAsset.length} bytes)`);
  }

  const sidecarOutcome = await verifyManifestBytes(result.manifest, []);
  console.log('\nDEBUG verifyManifestBytes on extracted sidecar:', JSON.stringify(sidecarOutcome, null, 2));
}

run().catch((err) => {
  console.error('Error:', err);
  process.exit(1);
});
