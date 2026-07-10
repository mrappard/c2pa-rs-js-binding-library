import { signAsset, verifyAsset } from '../src/index.ts';
import { readFileSync, writeFileSync, mkdirSync } from 'fs';
import { join, dirname, resolve } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = resolve(__dirname, '..');

type Environment = {
  /** Path to the input PDF (relative to project root or absolute). */
  inputFile: string;
  /** Where to write the signed PDF (relative to project root or absolute). */
  outputFile: string;
  /** Path to the signing certificate PEM file. */
  signcert: string;
  /** Path to the private key file. */
  pkey: string;
  /** Signing algorithm: "es256" | "es384" | "es512" | "ps256" | "ps384" | "ps512" | "ed25519". */
  alg: string;
  /** Optional RFC 3161 timestamp authority URL. Leave empty to omit a timestamp. */
  tsaUrl?: string;
  /**
   * Optional manifest ID to embed. When set, this becomes the manifest label used during signing.
   * Must be "urn:c2pa:<v4-uuid>" format, e.g. "urn:c2pa:828b19c8-a70e-4a3f-84df-763967f7d372".
   * Leave empty to let c2pa-rs auto-generate a UUID — the script will print it after signing
   * so you can copy it back here for future runs.
   */
  manifestId?: string;
  /** C2PA manifest definition to embed. */
  manifest: {
    claim_generator_info: { name: string; [key: string]: unknown }[];
    title: string;
    assertions: { label: string; data: unknown }[];
    [key: string]: unknown;
  };
};

const env: Environment = JSON.parse(
  readFileSync(join(__dirname, 'environment.json'), 'utf-8')
).signPdf;

const inputPath = resolve(root, env.inputFile);
const outputPath = resolve(root, env.outputFile);
const signcert = new Uint8Array(readFileSync(resolve(root, env.signcert)));
const pkey = new Uint8Array(readFileSync(resolve(root, env.pkey)));

async function run() {
  console.log(`Input:  ${inputPath}`);
  console.log(`Output: ${outputPath}`);
  console.log(`Alg:    ${env.alg}`);
  if (env.tsaUrl) console.log(`TSA:    ${env.tsaUrl}`);
  if (env.manifestId) console.log(`Manifest ID: ${env.manifestId}`);
  console.log('');

  const asset = new Uint8Array(readFileSync(inputPath));

  // If a manifest ID is specified, embed it as the manifest label.
  const manifestDefinition = env.manifestId
    ? { ...env.manifest, label: env.manifestId }
    : env.manifest;

  const result = await signAsset({
    format: 'application/pdf',
    asset,
    manifestDefinition,
    signcert,
    pkey,
    alg: env.alg as any,
    tsaUrl: env.tsaUrl || undefined,
  });

  mkdirSync(dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, result.signedAsset);

  console.log(`Signed PDF written to: ${outputPath}`);
  console.log(`Manifest size: ${result.manifest.length} bytes`);

  // Parse the signed PDF to report the embedded manifest ID.
  const outcome = await verifyAsset('application/pdf', result.signedAsset, []);
  const store = outcome.manifestStore;
  const allIds = store ? Object.keys(store.manifests) : [];
  const activeId = store?.activeManifest ?? null;

  if (activeId) {
    console.log(`\nEmbedded manifest ID: ${activeId}`);
    if (allIds.length > 1) {
      console.log(`All IDs in store:`);
      allIds.forEach((id) => console.log(`  ${id}${id === activeId ? ' (active)' : ''}`));
    }
  }
}

run().catch((err) => {
  console.error('Error:', err);
  process.exit(1);
});
