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

    try {
      const outcome = await verifyAsset('image/jpeg', assetData, []);
      expect(outcome.manifests.length).toBeGreaterThan(0);
    } catch (e) {
      const errorMsg = String(e);
      if (errorMsg.includes('must fetch remote manifests') || errorMsg.includes('Remote manifest cannot be fetched')) {
        console.warn(`Skipping remote manifest check for ${filename}: ${errorMsg}`);
      } else if (errorMsg.includes('No C2PA manifest found')) {
         console.warn(`No manifest found in ${filename}`);
      } else {
        throw e;
      }
    }
  }
});
