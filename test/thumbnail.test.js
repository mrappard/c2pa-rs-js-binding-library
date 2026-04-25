import { expect, test } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import { signAssetWithThumbnail, verifyAsset } from '../src/index';

const SAMPLE_DIR = join(__dirname, '../examples/c2pa-rs-text-support/cli/sample');
const IMAGE_DIR = join(__dirname, 'assets/image/good');

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

test('sign a JPEG with a JPEG thumbnail and verify thumbnail is present', async () => {
  const { signcert, pkey, certPem } = loadCerts();
  const assetBytes = new Uint8Array(readFileSync(join(IMAGE_DIR, 'jpeg', 'Firefly_tabby_cat.jpg')));
  // Use a small JPEG from the same directory as the thumbnail.
  const thumbnailBytes = new Uint8Array(readFileSync(join(IMAGE_DIR, 'jpeg', 'car-es-Ps-Cr.jpg')));

  const result = await signAssetWithThumbnail(
    'image/jpeg',
    assetBytes,
    makeManifest('tabby_cat.jpg'),
    signcert,
    pkey,
    'es256',
    'image/jpeg',
    thumbnailBytes
  );

  expect(result.signedAsset).toBeDefined();
  expect(result.manifest).toBeDefined();

  const outcome = await verifyAsset('image/jpeg', result.signedAsset, [certPem]);
  expect(outcome.manifests.length).toBeGreaterThan(0);

  const manifest = outcome.manifests[0];
  expect(manifest.thumbnail).toBeDefined();
  expect(manifest.thumbnail.format).toBe('image/jpeg');
  expect(manifest.thumbnail.data.length).toBeGreaterThan(0);
});

test('sign a PNG with a PNG thumbnail and verify thumbnail is present', async () => {
  const { signcert, pkey, certPem } = loadCerts();
  const assetBytes = new Uint8Array(readFileSync(join(IMAGE_DIR, 'png', 'ChatGPT_Image.png')));
  const thumbnailBytes = new Uint8Array(readFileSync(join(IMAGE_DIR, 'png', 'ChatGPT_Image.png')));

  const result = await signAssetWithThumbnail(
    'image/png',
    assetBytes,
    makeManifest('ChatGPT_Image.png'),
    signcert,
    pkey,
    'es256',
    'image/png',
    thumbnailBytes
  );

  expect(result.signedAsset).toBeDefined();

  const outcome = await verifyAsset('image/png', result.signedAsset, [certPem]);
  expect(outcome.manifests.length).toBeGreaterThan(0);

  const manifest = outcome.manifests[0];
  expect(manifest.thumbnail).toBeDefined();
  expect(manifest.thumbnail.format).toBe('image/png');
  expect(manifest.thumbnail.data.length).toBeGreaterThan(0);
});

test('signAsset without thumbnail leaves thumbnail undefined', async () => {
  const { signcert, pkey, certPem } = loadCerts();
  const assetBytes = new Uint8Array(readFileSync(join(IMAGE_DIR, 'jpeg', 'Firefly_tabby_cat.jpg')));

  const { signAsset } = await import('../src/index');
  const result = await signAsset(
    'image/jpeg',
    assetBytes,
    makeManifest('no_thumbnail.jpg'),
    signcert,
    pkey,
    'es256'
  );

  const outcome = await verifyAsset('image/jpeg', result.signedAsset, [certPem]);
  expect(outcome.manifests[0].thumbnail == null).toBe(true);
});
