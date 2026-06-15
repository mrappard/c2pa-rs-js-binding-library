import { expect, test } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import { verifyAsset, getResource } from '../src/index';

const IMAGE_DIR = join(__dirname, 'assets/image/good/png');

// Per C2PA spec §2.2: the icon is referenced from claim_generator_info[].icon
// as a hashed-uri-map { url, hash, alg }. The url is a self#jumbf URI pointing
// to an embedded data assertion with label c2pa.icon.
test('extract icon from claim_generator_info hashed URI per C2PA spec', async () => {
  const assetBytes = new Uint8Array(readFileSync(join(IMAGE_DIR, 'ChatGPT_Image_With_Icon.png')));

  // Step 1: parse the manifest to discover the icon URI
  const outcome = await verifyAsset('image/png', assetBytes, []);
  expect(outcome.manifests.length).toBeGreaterThan(0);

  const manifest = outcome.manifests[0];
  const generatorInfo = manifest.claimGeneratorInfo;
  expect(Array.isArray(generatorInfo) && generatorInfo.length > 0).toBe(true);

  // Step 2: locate the icon entry in claim_generator_info.
  // The c2pa Rust crate serializes icon as a ResourceRef: { format, identifier }
  // where identifier is the self#jumbf URI to the embedded data assertion.
  const iconEntry = generatorInfo.find((entry) => entry.icon != null);
  expect(iconEntry).toBeDefined();

  const { format: iconFormat, identifier: iconUri } = iconEntry.icon;
  expect(typeof iconUri).toBe('string');
  expect(iconUri.startsWith('self#jumbf=')).toBe(true);
  expect(iconFormat).toBe('image/svg+xml');

  // Step 3: fetch the embedded icon resource using the URI from the manifest
  const iconBytes = await getResource('image/png', assetBytes, iconUri);
  expect(iconBytes.length).toBeGreaterThan(0);

  // Step 4: the format declared in the manifest assertion is image/svg+xml
  const text = new TextDecoder().decode(iconBytes);
  expect(text.trim().startsWith('<svg') || text.trim().startsWith('<?xml')).toBe(true);
});
