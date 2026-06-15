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

// A self-signed CA certificate unrelated to the signing cert in `es256_certs.pem`,
// used to verify that trust validation is rejected when the chain doesn't match.
const UNRELATED_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIICGzCCAcICCQD/WSahvlqufDAKBggqhkjOPQQDAjAcMRowGAYDVQQDDBFVbnJl
bGF0ZWQgVGVzdCBDQTAeFw0yNjA2MTUxNTM4MDFaFw0zNjA2MTIxNTM4MDFaMBwx
GjAYBgNVBAMMEVVucmVsYXRlZCBUZXN0IENBMIIBSzCCAQMGByqGSM49AgEwgfcC
AQEwLAYHKoZIzj0BAQIhAP////8AAAABAAAAAAAAAAAAAAAA////////////////
MFsEIP////8AAAABAAAAAAAAAAAAAAAA///////////////8BCBaxjXYqjqT57Pr
vVV2mIa8ZR0GsMxTsPY7zjw+J9JgSwMVAMSdNgiG5wSTamZ44ROdJreBn36QBEEE
axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54W
K84zV2sxXs7LtkBoN79R9QIhAP////8AAAAA//////////+85vqtpxeehPO5ysL8
YyVRAgEBA0IABPG54Ez1jB2qwY3gqRebbGkH/2qwqZs2MxuQynrk9aGJ9tsHY21C
4EoR9izOtuwiLzEjbV/RUta8vrcrwOuFyb8wCgYIKoZIzj0EAwIDRwAwRAIgKktB
iKav5cw7ktV2SiCJOz/s1SrsBmnFV1yhbw4d4XUCICFmqg8jNrdOO/SILMWPgGxM
YQzqX1xapzoiY2DhUjI2
-----END CERTIFICATE-----`;

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

  const result = await signAsset({ format: 'image/svg+xml', asset: assetData, manifestDefinition: makeManifest('sample.svg'), signcert, pkey, alg: 'es256' });
  expect(result.signedAsset).toBeDefined();
  expect(result.manifest).toBeDefined();

  const outcome = await verifyAsset('image/svg+xml', result.signedAsset, [certPem]);
  assertSignedManifest(outcome);
});

test('sign and verify a JPEG asset', async () => {
  const { signcert, pkey, certPem } = loadCerts();
  const assetData = new Uint8Array(readFileSync(join(IMAGE_DIR, 'jpeg', 'Firefly_tabby_cat.jpg')));

  const result = await signAsset({ format: 'image/jpeg', asset: assetData, manifestDefinition: makeManifest('Firefly_tabby_cat.jpg'), signcert, pkey, alg: 'es256' });
  expect(result.signedAsset).toBeDefined();
  expect(result.manifest).toBeDefined();

  const outcome = await verifyAsset('image/jpeg', result.signedAsset, [certPem]);
  assertSignedManifest(outcome);
});

test('sign and verify a PNG asset', async () => {
  const { signcert, pkey, certPem } = loadCerts();
  const assetData = new Uint8Array(readFileSync(join(IMAGE_DIR, 'png', 'ChatGPT_Image.png')));

  const result = await signAsset({ format: 'image/png', asset: assetData, manifestDefinition: makeManifest('ChatGPT_Image.png'), signcert, pkey, alg: 'es256' });
  expect(result.signedAsset).toBeDefined();
  expect(result.manifest).toBeDefined();

  const outcome = await verifyAsset('image/png', result.signedAsset, [certPem]);
  assertSignedManifest(outcome);
});

test('verifyAsset reports state=false when no trusted certificates are provided', async () => {
  const { signcert, pkey } = loadCerts();
  const assetData = new Uint8Array(readFileSync(join(IMAGE_DIR, 'jpeg', 'Firefly_tabby_cat.jpg')));

  const result = await signAsset({ format: 'image/jpeg', asset: assetData, manifestDefinition: makeManifest('Firefly_tabby_cat.jpg'), signcert, pkey, alg: 'es256' });

  const outcome = await verifyAsset('image/jpeg', result.signedAsset, []);
  expect(outcome.state).toBe(false);
});

test('verifyAsset reports state=true when the signing chain matches a trusted certificate', async () => {
  const { signcert, pkey, certPem } = loadCerts();
  const assetData = new Uint8Array(readFileSync(join(IMAGE_DIR, 'jpeg', 'Firefly_tabby_cat.jpg')));

  const result = await signAsset({ format: 'image/jpeg', asset: assetData, manifestDefinition: makeManifest('Firefly_tabby_cat.jpg'), signcert, pkey, alg: 'es256' });

  const outcome = await verifyAsset('image/jpeg', result.signedAsset, [certPem]);
  expect(outcome.state).toBe(true);
});

test('verifyAsset reports state=false when the signing chain does not match an unrelated trusted certificate', async () => {
  const { signcert, pkey } = loadCerts();
  const assetData = new Uint8Array(readFileSync(join(IMAGE_DIR, 'jpeg', 'Firefly_tabby_cat.jpg')));

  const result = await signAsset({ format: 'image/jpeg', asset: assetData, manifestDefinition: makeManifest('Firefly_tabby_cat.jpg'), signcert, pkey, alg: 'es256' });

  const outcome = await verifyAsset('image/jpeg', result.signedAsset, [UNRELATED_CERT_PEM]);
  expect(outcome.state).toBe(false);
});
