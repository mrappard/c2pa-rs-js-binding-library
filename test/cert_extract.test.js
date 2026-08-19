import { expect, test } from 'vitest';
import { signAsset, getSigningCertificateChain } from '../src/index';
import { readFileSync } from 'fs';
import { join } from 'path';

const ASSETS_DIR = join(__dirname, 'assets');
const IMAGE_DIR = join(ASSETS_DIR, 'image', 'good');
const SAMPLE_DIR = join(__dirname, 'assets/sample');

test('extract signing cert chain', async () => {
  const signcert = new Uint8Array(readFileSync(join(SAMPLE_DIR, 'es256_certs.pem')));
  const pkey = new Uint8Array(readFileSync(join(SAMPLE_DIR, 'es256_private.key')));
  const assetData = new Uint8Array(readFileSync(join(IMAGE_DIR, 'jpeg', 'Firefly_tabby_cat.jpg')));

  const result = await signAsset({ format: 'image/jpeg', asset: assetData, manifestDefinition: { claim_generator_info: [{ name: 'test_generator' }], title: 't', assertions: [{ label: 'c2pa.actions', data: { actions: [{ action: 'c2pa.created', digitalSourceType: 'http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture' }] } }] }, signcert, pkey, alg: 'es256' });

  const chain = await getSigningCertificateChain('image/jpeg', result.signedAsset);
  console.log(chain);
  expect(chain).toContain('BEGIN CERTIFICATE');
});
