import { expect, test } from 'vitest';
import { signAsset, verifyAsset } from '../src/index';
import { readFileSync } from 'fs';
import { join } from 'path';

const ASSETS_DIR = join(__dirname, 'assets');
const IMAGE_DIR = join(ASSETS_DIR, 'image', 'good');
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

function assertSignedManifest(outcome, label) {
  expect(outcome.manifests.length).toBeGreaterThan(0);
  
  const firstManifest = outcome.manifests[0];
  expect(firstManifest.claimGenerator !== undefined).toBe(true);
  if (firstManifest.claimGenerator === null) {
    expect(firstManifest.claimGeneratorInfo).toBeDefined();
    expect(firstManifest.claimGeneratorInfo).not.toBeNull();
    expect(firstManifest.claimGeneratorInfo[0].name).toBe('test_generator');
  } else {
    expect(typeof firstManifest.claimGenerator).toBe('string');
  }

  const store = outcome.manifestStore;
  const activeManifest = store.manifests[store.activeManifest];
  expect(activeManifest.claimGenerator !== undefined).toBe(true);
  if (activeManifest.claimGenerator === null) {
    expect(activeManifest.claimGeneratorInfo).toBeDefined();
    expect(activeManifest.claimGeneratorInfo).not.toBeNull();
    expect(activeManifest.claimGeneratorInfo[0].name).toBe('test_generator');
  } else {
    expect(typeof activeManifest.claimGenerator).toBe('string');
  }
}

test('sign and verify an SVG asset', async () => {
  const { signcert, pkey, certPem } = loadCerts();
  const assetData = new Uint8Array(readFileSync(join(ASSETS_DIR, 'sample.svg')));

  const result = await signAsset('image/svg+xml', assetData, makeManifest('sample.svg'), signcert, pkey, 'es256');
  expect(result.signedAsset).toBeDefined();
  expect(result.manifest).toBeDefined();

  const outcome = await verifyAsset('image/svg+xml', result.signedAsset, [certPem]);
  assertSignedManifest(outcome);
});

test('sign and verify a JPEG asset', async () => {
  const { signcert, pkey, certPem } = loadCerts();
  const assetData = new Uint8Array(readFileSync(join(IMAGE_DIR, 'jpeg', 'Firefly_tabby_cat.jpg')));

  const result = await signAsset('image/jpeg', assetData, makeManifest('Firefly_tabby_cat.jpg'), signcert, pkey, 'es256');
  expect(result.signedAsset).toBeDefined();
  expect(result.manifest).toBeDefined();

  const outcome = await verifyAsset('image/jpeg', result.signedAsset, [certPem]);
  assertSignedManifest(outcome);
});

test('sign and verify a PNG asset', async () => {
  const { signcert, pkey, certPem } = loadCerts();
  const assetData = new Uint8Array(readFileSync(join(IMAGE_DIR, 'png', 'ChatGPT_Image.png')));

  const result = await signAsset('image/png', assetData, makeManifest('ChatGPT_Image.png'), signcert, pkey, 'es256');
  expect(result.signedAsset).toBeDefined();
  expect(result.manifest).toBeDefined();

  const outcome = await verifyAsset('image/png', result.signedAsset, [certPem]);
  assertSignedManifest(outcome);
});
