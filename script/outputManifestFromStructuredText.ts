import {
  signJsoncAsset,
  signMarkdownAsset,
  signXmlAsset,
  verifyJsoncAsset,
  verifyMarkdownAsset,
  verifyXmlAsset,
} from '../src/index.ts';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SAMPLE_DIR = join(__dirname, '../examples/c2pa-rs-text-support/cli/sample');

const SAMPLE_JSONC = `{
  // JSONC keeps user comments
  "name": "settings",
  "enabled": true,
  "items": [
    "alpha",
    "beta",
  ],
}`;

const SAMPLE_XML = `<?xml version="1.0" encoding="UTF-8"?>
<settings>
  <enabled>true</enabled>
</settings>
`;

const SAMPLE_MD = `# Sample Document

This is a markdown document with **content credentials**.
`;

function mapToObject(value: any): any {
  if (value instanceof Map) {
    return Object.fromEntries(
      Array.from(value.entries()).map(([key, val]) => [key, mapToObject(val)])
    );
  }

  if (Array.isArray(value)) {
    return value.map(mapToObject);
  }

  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([key, val]) => [key, mapToObject(val)])
    );
  }

  return value;
}

function loadCerts() {
  return {
    signcert: new Uint8Array(readFileSync(join(SAMPLE_DIR, 'es256_certs.pem'))),
    pkey: new Uint8Array(readFileSync(join(SAMPLE_DIR, 'es256_private.key'))),
    certPem: readFileSync(join(SAMPLE_DIR, 'es256_certs.pem'), 'utf-8'),
  };
}

function makeManifest(title: string) {
  return {
    claim_generator_info: [{ name: 'script_generator' }],
    title,
    assertions: [{ label: 'c2pa.actions', data: { actions: [{ action: 'c2pa.created' }] } }],
  };
}

async function printManifestStore(
  label: string,
  sign: () => Promise<{ signedAsset: Uint8Array }>,
  verify: (asset: Uint8Array, trustedCertificates: string[]) => Promise<any>,
  certPem: string
) {
  console.log(`\n=== ${label} ===`);

  const result = await sign();
  const outcome = await verify(result.signedAsset, [certPem]);

  if (outcome.manifests.length === 0) {
    console.log('No manifests found.');
    return;
  }

  console.log(JSON.stringify(mapToObject(outcome.manifestStore), null, 2));
}

async function run() {
  const { signcert, pkey, certPem } = loadCerts();

  await printManifestStore(
    'JSONC',
    () => signJsoncAsset(SAMPLE_JSONC, makeManifest('settings.jsonc'), signcert, pkey, 'es256'),
    verifyJsoncAsset,
    certPem
  );

  await printManifestStore(
    'XML',
    () => signXmlAsset(SAMPLE_XML, makeManifest('settings.xml'), signcert, pkey, 'es256'),
    verifyXmlAsset,
    certPem
  );

  await printManifestStore(
    'Markdown',
    () => signMarkdownAsset(SAMPLE_MD, makeManifest('document.md'), signcert, pkey, 'es256'),
    verifyMarkdownAsset,
    certPem
  );
}

run().catch((error) => {
  console.error('Error processing structured-text assets:', error);
  process.exitCode = 1;
});
