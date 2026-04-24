import { expect, test } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import {
  cleanAsset,
  cleanJsoncAsset,
  signAsset,
  signJsoncAsset,
  verifyAsset,
  verifyJsoncAsset,
} from '../src/index';

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

test('cleanAsset removes C2PA data from a signed PNG', async () => {
  const { signcert, pkey, certPem } = loadCerts();
  const assetData = new Uint8Array(readFileSync(join(IMAGE_DIR, 'png', 'ChatGPT_Image.png')));

  const signed = await signAsset(
    'image/png',
    assetData,
    makeManifest('ChatGPT_Image.png'),
    signcert,
    pkey,
    'es256'
  );

  const verifiedSigned = await verifyAsset('image/png', signed.signedAsset, [certPem]);
  expect(verifiedSigned.manifests.length).toBeGreaterThan(0);

  const cleaned = cleanAsset('image/png', signed.signedAsset);
  await expect(verifyAsset('image/png', cleaned, [certPem])).rejects.toThrow(/no JUMBF data found/i);
});

test('cleanJsoncAsset removes C2PA data from a signed JSONC asset', async () => {
  const { signcert, pkey, certPem } = loadCerts();
  const jsonc = `{
  // JSONC keeps comments
  "enabled": true,
}`;

  const signed = await signJsoncAsset(
    jsonc,
    makeManifest('settings.jsonc'),
    signcert,
    pkey,
    'es256'
  );

  const verifiedSigned = await verifyJsoncAsset(signed.signedAsset, [certPem]);
  expect(verifiedSigned.manifests.length).toBeGreaterThan(0);

  const cleaned = cleanJsoncAsset(signed.signedAsset);
  await expect(verifyJsoncAsset(cleaned, [certPem])).rejects.toThrow(/no JUMBF data found/i);
  expect(new TextDecoder().decode(cleaned)).not.toContain('BEGIN C2PA MANIFEST');
});

test('cleanAsset is idempotent once C2PA data has been removed', async () => {
  const { signcert, pkey } = loadCerts();
  const assetData = new Uint8Array(readFileSync(join(IMAGE_DIR, 'png', 'ChatGPT_Image.png')));

  const signed = await signAsset(
    'image/png',
    assetData,
    makeManifest('ChatGPT_Image.png'),
    signcert,
    pkey,
    'es256'
  );

  const cleanedOnce = cleanAsset('image/png', signed.signedAsset);
  const cleanedTwice = cleanAsset('image/png', cleanedOnce);

  expect(cleanedTwice).toEqual(cleanedOnce);
});
