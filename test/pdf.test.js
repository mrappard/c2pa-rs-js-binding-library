import { expect, test } from 'vitest';
import { signAsset, verifyAsset } from '../src/index';
import { readFileSync, writeFileSync } from 'fs';
import { join } from 'path';

const ASSETS_DIR = join(__dirname, 'assets');
const SAMPLE_DIR = join(__dirname, '../examples/c2pa-rs-text-support/cli/sample');

function loadCerts() {
  return {
    signcert: new Uint8Array(readFileSync(join(SAMPLE_DIR, 'es256_certs.pem'))),
    pkey: new Uint8Array(readFileSync(join(SAMPLE_DIR, 'es256_private.key'))),
    certPem: readFileSync(join(SAMPLE_DIR, 'es256_certs.pem'), 'utf-8'),
  };
}

function makeManifest(title) {
  return {
    claim_generator_info: [{ name: 'test_generator' }],
    title,
    assertions: [{ label: 'c2pa.actions', data: { actions: [{ action: 'c2pa.created' }] } }],
  };
}

test('sign and verify a PDF asset', async () => {
  const { signcert, pkey, certPem } = loadCerts();
  const assetData = new Uint8Array(readFileSync(join(ASSETS_DIR, 'TestDoc.pdf')));

  const result = await signAsset({ format: 'application/pdf', asset: assetData, manifestDefinition: makeManifest('TestDoc.pdf'), signcert, pkey, alg: 'es256' });
  expect(result.signedAsset).toBeDefined();
  expect(result.manifest).toBeDefined();
  expect(result.signedAsset.length).toBeGreaterThan(0);

  const outcome = await verifyAsset('application/pdf', result.signedAsset, [certPem]);
  expect(outcome).toBeDefined();
  expect(outcome.manifests.length).toBeGreaterThan(0);

  const manifest = outcome.manifests[0];
  expect(manifest.id).toBeDefined();
  expect(manifest.title).toBe('TestDoc.pdf');

  const store = outcome.manifestStore;
  expect(store).toBeDefined();
  expect(store.activeManifest).toBeDefined();
  const activeManifest = store.manifests[store.activeManifest];
  expect(activeManifest.claimGeneratorInfo[0].name).toBe('test_generator');
});

test('verify an unsigned PDF throws JumbfNotFound', async () => {
  const assetData = new Uint8Array(readFileSync(join(ASSETS_DIR, 'TestDoc.pdf')));
  await expect(verifyAsset('application/pdf', assetData, [])).rejects.toThrow();
});
