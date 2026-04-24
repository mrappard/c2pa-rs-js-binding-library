import { expect, test } from 'vitest';
import { verifyAsset } from '../src/index';
import { readFileSync } from 'fs';
import { join } from 'path';

const ASSETS_DIR = join(__dirname, 'assets', 'image', 'good');

test('verify JPEG asset with C2PA manifest', async () => {
  const imagePath = join(ASSETS_DIR, 'jpeg', 'Firefly_tabby_cat.jpg');
  const buffer = readFileSync(imagePath);
  const assetData = new Uint8Array(buffer);

  // We use 'image/jpeg' as the format
  const outcome = await verifyAsset('image/jpeg', assetData, []);

  expect(outcome).toBeDefined();
  expect(outcome.manifests.length).toBeGreaterThan(0);
  
  const manifest = outcome.manifests[0];
  expect(manifest.id).toBeDefined();
});

test('verify PNG asset with C2PA manifest', async () => {
  const imagePath = join(ASSETS_DIR, 'png', 'ChatGPT_Image.png');
  const buffer = readFileSync(imagePath);
  const assetData = new Uint8Array(buffer);

  // We use 'image/png' as the format
  const outcome = await verifyAsset('image/png', assetData, []);

  expect(outcome).toBeDefined();
  expect(outcome.manifests.length).toBeGreaterThan(0);
  
  const manifest = outcome.manifests[0];
  expect(manifest.id).toBeDefined();
});

test('verify multiple JPEG assets', async () => {
  const jpegs = [
    'car-es-Ps-Cr.jpg',
    'cloudscape-ACA-Cr.jpeg',
    'crater-lake-cr.jpg'
  ];

  for (const filename of jpegs) {
    const imagePath = join(ASSETS_DIR, 'jpeg', filename);
    const buffer = readFileSync(imagePath);
    const assetData = new Uint8Array(buffer);

    const outcome = await verifyAsset('image/jpeg', assetData, []);
    expect(outcome.manifests.length).toBeGreaterThan(0);
    console.log(`Successfully verified ${filename} with manifest ID: ${outcome.manifests[0].id}`);
  }
});
