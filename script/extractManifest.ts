import { verifyAsset, verifyAssetSignatureOnly } from '../src/index.ts';
import { readFileSync, writeFileSync, mkdirSync } from 'fs';
import { join, dirname, resolve, extname, basename } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = resolve(__dirname, '..');

type Environment = {
  /** Path to the asset to extract the manifest from (relative to project root or absolute). */
  inputFile: string;
  /** MIME type of the asset, e.g. "image/jpeg", "image/png", "image/svg+xml", "application/pdf". */
  format: string;
  /** Where to write the extracted manifest JSON (relative to project root or absolute). Defaults to script/output/<filename>.json. */
  outputFile?: string;
  /** Array of paths to PEM files used as trust anchors. If empty, trust is not verified. */
  trustedCertificates?: string[];
  /** When true, uses verifyAssetSignatureOnly — checks crypto validity but ignores asset hash mismatches. */
  signatureOnly?: boolean;
};

const env: Environment = JSON.parse(
  readFileSync(join(__dirname, 'environment.json'), 'utf-8')
).extractManifest;

const inputPath = resolve(root, env.inputFile);
const outputPath = env.outputFile
  ? resolve(root, env.outputFile)
  : join(__dirname, 'output', `${basename(env.inputFile, extname(env.inputFile))}.json`);

const trustedCertificates: string[] = (env.trustedCertificates ?? []).map((certPath) =>
  readFileSync(resolve(root, certPath), 'utf-8')
);

async function run() {
  console.log(`Input:  ${inputPath}`);
  console.log(`Format: ${env.format}`);
  console.log(`Trust:  ${trustedCertificates.length} certificate(s)`);
  console.log(`Mode:   ${env.signatureOnly ? 'signature-only (hash ignored)' : 'full verification'}`);
  console.log('');

  const asset = new Uint8Array(readFileSync(inputPath));

  const outcome = env.signatureOnly
    ? await verifyAssetSignatureOnly(env.format as any, asset, trustedCertificates)
    : await verifyAsset(env.format as any, asset, trustedCertificates);

  if (env.signatureOnly) {
    const r = outcome as Awaited<ReturnType<typeof verifyAssetSignatureOnly>>;
    console.log(`Signature valid: ${r.signatureValid}`);
    console.log(`Trusted:         ${r.trusted}`);
  } else {
    const r = outcome as Awaited<ReturnType<typeof verifyAsset>>;
    console.log(`State:   ${r.state ? 'trusted' : 'not trusted'}`);
  }

  if (outcome.manifests.length === 0) {
    console.log('No manifests found in this file.');
    return;
  }

  console.log(`Manifests found: ${outcome.manifests.length}`);

  mkdirSync(dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, JSON.stringify(outcome.manifestStore, null, 2));
  console.log(`\nWrote manifest to: ${outputPath}`);
}

run().catch((err) => {
  console.error('Error:', err);
  process.exit(1);
});
