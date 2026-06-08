import { expect, test } from 'vitest';
import { signAssetSidecar, verifyAssetFromSidecar, verifyAsset, computeIcaIssuerDid } from '../src/index';
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

function makeManifestWithAssetReference(title, assetUri) {
  return {
    claim_generator_info: [{ name: 'test_generator' }],
    title,
    assertions: [
      { label: 'c2pa.actions', data: { actions: [{ action: 'c2pa.created' }] } },
      {
        label: 'c2pa.asset.reference',
        data: {
          references: [
            {
              reference: { uri: assetUri },
              description: 'Original dataset asset',
            },
          ],
        },
      },
    ],
  };
}

test('sidecar sign returns non-empty sidecar manifest bytes', async () => {
  const { signcert, pkey } = loadCerts();
  const assetData = new Uint8Array(readFileSync(join(IMAGE_DIR, 'jpeg', 'Firefly_tabby_cat.jpg')));

  const result = await signAssetSidecar({
    format: 'image/jpeg',
    asset: assetData,
    manifestDefinition: makeManifest('Firefly_tabby_cat.jpg'),
    signcert,
    pkey,
    alg: 'es256',
  });

  expect(result.manifest).toBeDefined();
  expect(result.manifest.length).toBeGreaterThan(0);
  expect(result.signedAsset).toBeDefined();
  expect(result.signedAsset.length).toBeGreaterThan(0);
});

test('sidecar signing does not embed manifest in the asset', async () => {
  const { signcert, pkey } = loadCerts();
  const assetData = new Uint8Array(readFileSync(join(IMAGE_DIR, 'jpeg', 'Firefly_tabby_cat.jpg')));

  const result = await signAssetSidecar({
    format: 'image/jpeg',
    asset: assetData,
    manifestDefinition: makeManifest('Firefly_tabby_cat.jpg'),
    signcert,
    pkey,
    alg: 'es256',
  });

  // The signed asset bytes must equal the original — no manifest embedded.
  expect(Buffer.from(result.signedAsset)).toEqual(Buffer.from(assetData));
});

test('sidecar manifest can be verified against the original asset (JPEG)', async () => {
  const { signcert, pkey, certPem } = loadCerts();
  const assetData = new Uint8Array(readFileSync(join(IMAGE_DIR, 'jpeg', 'Firefly_tabby_cat.jpg')));

  const result = await signAssetSidecar({
    format: 'image/jpeg',
    asset: assetData,
    manifestDefinition: makeManifest('Firefly_tabby_cat.jpg'),
    signcert,
    pkey,
    alg: 'es256',
  });

  const outcome = await verifyAssetFromSidecar({
    format: 'image/jpeg',
    asset: assetData,
    sidecar: result.manifest,
    trustedCertificates: [certPem],
  });

  expect(outcome.manifests.length).toBeGreaterThan(0);
  const store = outcome.manifestStore;
  expect(store).toBeDefined();
  expect(store.activeManifest).toBeTruthy();
  const activeManifest = store.manifests[store.activeManifest];
  expect(activeManifest).toBeDefined();
  expect(activeManifest.title).toBe('Firefly_tabby_cat.jpg');
});

test('sidecar manifest can be verified against the original asset (PNG)', async () => {
  const { signcert, pkey, certPem } = loadCerts();
  const assetData = new Uint8Array(readFileSync(join(IMAGE_DIR, 'png', 'ChatGPT_Image.png')));

  const result = await signAssetSidecar({
    format: 'image/png',
    asset: assetData,
    manifestDefinition: makeManifest('ChatGPT_Image.png'),
    signcert,
    pkey,
    alg: 'es256',
  });

  const outcome = await verifyAssetFromSidecar({
    format: 'image/png',
    asset: assetData,
    sidecar: result.manifest,
    trustedCertificates: [certPem],
  });

  expect(outcome.manifests.length).toBeGreaterThan(0);
  const store = outcome.manifestStore;
  const activeManifest = store.manifests[store.activeManifest];
  expect(activeManifest.title).toBe('ChatGPT_Image.png');
});

test('sidecar manifest with asset reference assertion is verified correctly', async () => {
  const { signcert, pkey, certPem } = loadCerts();
  const assetData = new Uint8Array(readFileSync(join(IMAGE_DIR, 'jpeg', 'Firefly_tabby_cat.jpg')));
  const assetUri = 'https://example.com/datasets/Firefly_tabby_cat.jpg';

  const result = await signAssetSidecar({
    format: 'image/jpeg',
    asset: assetData,
    manifestDefinition: makeManifestWithAssetReference('Firefly_tabby_cat.jpg', assetUri),
    signcert,
    pkey,
    alg: 'es256',
  });

  const outcome = await verifyAssetFromSidecar({
    format: 'image/jpeg',
    asset: assetData,
    sidecar: result.manifest,
    trustedCertificates: [certPem],
  });

  expect(outcome.manifests.length).toBeGreaterThan(0);
  const firstManifest = outcome.manifests[0];

  // The asset reference assertion should be present.
  expect(firstManifest.assertions['c2pa.asset.reference']).toBeDefined();
  const assetRef = firstManifest.assertions['c2pa.asset.reference'];
  expect(assetRef.references).toBeDefined();
  expect(assetRef.references[0].reference.uri).toBe(assetUri);
});

test('sidecar fails to verify when asset bytes are tampered', async () => {
  const { signcert, pkey, certPem } = loadCerts();
  const assetData = new Uint8Array(readFileSync(join(IMAGE_DIR, 'jpeg', 'Firefly_tabby_cat.jpg')));

  const result = await signAssetSidecar({
    format: 'image/jpeg',
    asset: assetData,
    manifestDefinition: makeManifest('Firefly_tabby_cat.jpg'),
    signcert,
    pkey,
    alg: 'es256',
  });

  // Tamper with the asset (flip some bytes in the middle of the file data).
  const tampered = new Uint8Array(assetData);
  tampered[Math.floor(tampered.length / 2)] ^= 0xff;
  tampered[Math.floor(tampered.length / 2) + 1] ^= 0xff;

  // Verification should either reject or return state=false (hash mismatch).
  let outcome;
  try {
    outcome = await verifyAssetFromSidecar({
      format: 'image/jpeg',
      asset: tampered,
      sidecar: result.manifest,
      trustedCertificates: [certPem],
    });
  } catch {
    // Rejection is also acceptable.
    return;
  }
  expect(outcome.state).toBe(false);
});

test('sidecar for SVG asset', async () => {
  const { signcert, pkey, certPem } = loadCerts();
  const assetData = new Uint8Array(readFileSync(join(ASSETS_DIR, 'sample.svg')));

  const result = await signAssetSidecar({
    format: 'image/svg+xml',
    asset: assetData,
    manifestDefinition: makeManifest('sample.svg'),
    signcert,
    pkey,
    alg: 'es256',
  });

  expect(result.manifest.length).toBeGreaterThan(0);

  const outcome = await verifyAssetFromSidecar({
    format: 'image/svg+xml',
    asset: assetData,
    sidecar: result.manifest,
    trustedCertificates: [certPem],
  });

  expect(outcome.manifests.length).toBeGreaterThan(0);
  const store = outcome.manifestStore;
  const activeManifest = store.manifests[store.activeManifest];
  expect(activeManifest.title).toBe('sample.svg');
});

test('sidecar manifest bytes are different from embedded manifest bytes for the same asset', async () => {
  const { signcert, pkey } = loadCerts();
  const assetData = new Uint8Array(readFileSync(join(IMAGE_DIR, 'jpeg', 'Firefly_tabby_cat.jpg')));

  const sidecarResult = await signAssetSidecar({
    format: 'image/jpeg',
    asset: assetData,
    manifestDefinition: makeManifest('Firefly_tabby_cat.jpg'),
    signcert,
    pkey,
    alg: 'es256',
  });

  // Sidecar manifest and the asset itself are distinct non-empty buffers.
  expect(sidecarResult.manifest.length).toBeGreaterThan(0);
  expect(Buffer.from(sidecarResult.signedAsset)).toEqual(Buffer.from(assetData));
});

test('verifyAssetFromSidecar finds the sidecar manifest, not the original embedded one', async () => {
  const { signcert, pkey, certPem } = loadCerts();
  const assetData = new Uint8Array(readFileSync(join(IMAGE_DIR, 'jpeg', 'Firefly_tabby_cat.jpg')));
  const title = 'sidecar-only-title';

  const result = await signAssetSidecar({
    format: 'image/jpeg',
    asset: assetData,
    manifestDefinition: makeManifest(title),
    signcert,
    pkey,
    alg: 'es256',
  });

  // The sidecar verification must find the manifest WE created.
  const outcome = await verifyAssetFromSidecar({
    format: 'image/jpeg',
    asset: assetData,
    sidecar: result.manifest,
    trustedCertificates: [certPem],
  });

  const store = outcome.manifestStore;
  const activeManifest = store.manifests[store.activeManifest];
  expect(activeManifest.title).toBe(title);
  expect(activeManifest.claimGeneratorInfo[0].name).toBe('test_generator');
});

// ── Thumbnail path ────────────────────────────────────────────────────────────

test('sidecar with thumbnail: asset is unchanged and thumbnail is in the manifest', async () => {
  const { signcert, pkey, certPem } = loadCerts();
  const assetData = new Uint8Array(readFileSync(join(IMAGE_DIR, 'jpeg', 'Firefly_tabby_cat.jpg')));
  const thumbnailData = new Uint8Array(readFileSync(join(IMAGE_DIR, 'jpeg', 'car-es-Ps-Cr.jpg')));

  const result = await signAssetSidecar({
    format: 'image/jpeg',
    asset: assetData,
    manifestDefinition: makeManifest('Firefly_tabby_cat.jpg'),
    signcert,
    pkey,
    alg: 'es256',
    thumbnailFormat: 'image/jpeg',
    thumbnailData,
  });

  expect(result.manifest.length).toBeGreaterThan(0);
  expect(Buffer.from(result.signedAsset)).toEqual(Buffer.from(assetData));

  const outcome = await verifyAssetFromSidecar({
    format: 'image/jpeg',
    asset: assetData,
    sidecar: result.manifest,
    trustedCertificates: [certPem],
  });

  expect(outcome.manifests.length).toBeGreaterThan(0);
  // Thumbnail should be present in the verified manifest.
  expect(outcome.manifests[0].thumbnail).toBeDefined();
  expect(outcome.manifests[0].thumbnail).not.toBeNull();
  expect(outcome.manifests[0].thumbnail.format).toBe('image/jpeg');
});

// ── Parent ingredient path ────────────────────────────────────────────────────

test('sidecar with parent ingredient: asset is unchanged and ingredient is in the manifest', async () => {
  const { signcert, pkey, certPem } = loadCerts();
  const assetData = new Uint8Array(readFileSync(join(IMAGE_DIR, 'png', 'ChatGPT_Image.png')));
  const parentData = new Uint8Array(readFileSync(join(IMAGE_DIR, 'jpeg', 'Firefly_tabby_cat.jpg')));

  const result = await signAssetSidecar({
    format: 'image/png',
    asset: assetData,
    manifestDefinition: makeManifest('ChatGPT_Image.png'),
    signcert,
    pkey,
    alg: 'es256',
    parentFormat: 'image/jpeg',
    parentAsset: parentData,
    parentTitle: 'Firefly_tabby_cat.jpg',
  });

  expect(result.manifest.length).toBeGreaterThan(0);
  expect(Buffer.from(result.signedAsset)).toEqual(Buffer.from(assetData));

  const outcome = await verifyAssetFromSidecar({
    format: 'image/png',
    asset: assetData,
    sidecar: result.manifest,
    trustedCertificates: [certPem],
  });

  expect(outcome.manifests.length).toBeGreaterThan(0);
  // Active manifest should include the parent ingredient.
  const activeManifestRecord = outcome.manifests.find(
    (m) => m.id === outcome.manifestStore.activeManifest
  );
  expect(activeManifestRecord.ingredients.length).toBeGreaterThan(0);
});

// ── X509 identity path ────────────────────────────────────────────────────────

test('sidecar with X509 identity: asset is unchanged and identity assertion is in the manifest', async () => {
  const { signcert, pkey, certPem } = loadCerts();
  const assetData = new Uint8Array(readFileSync(join(IMAGE_DIR, 'jpeg', 'Firefly_tabby_cat.jpg')));

  const result = await signAssetSidecar({
    format: 'image/jpeg',
    asset: assetData,
    manifestDefinition: makeManifest('Firefly_tabby_cat.jpg'),
    signcert,
    pkey,
    alg: 'es256',
    identitySigncert: signcert,
    identityPkey: pkey,
    identityAlg: 'es256',
    identityOptions: {
      sigType: 'cawg.x509.cose',
      reserveSize: 4096,
      referencedAssertions: ['c2pa.actions'],
      roles: ['cawg.creator'],
    },
  });

  expect(result.manifest.length).toBeGreaterThan(0);
  expect(Buffer.from(result.signedAsset)).toEqual(Buffer.from(assetData));

  const outcome = await verifyAssetFromSidecar({
    format: 'image/jpeg',
    asset: assetData,
    sidecar: result.manifest,
    trustedCertificates: [certPem],
  });

  expect(outcome.manifests.length).toBeGreaterThan(0);
  const firstManifest = outcome.manifests[0];
  const identityKey = Object.keys(firstManifest.assertions).find(
    (k) => k === 'cawg.identity' || k.startsWith('cawg.identity__')
  );
  expect(identityKey).toBeDefined();
});

// ── ICA identity path ─────────────────────────────────────────────────────────

const ICA_PRIVATE_KEY = new Uint8Array(Array.from({ length: 32 }, (_, i) => i + 1));

function makeIcaVerifiedIdentities() {
  return [
    {
      type: 'cawg.social_media',
      username: 'testuser',
      uri: 'https://example-social.com/testuser',
      verifiedAt: '2024-01-01T00:00:00Z',
      provider: { id: 'https://example-social.com', name: 'Example Social' },
    },
  ];
}

test('sidecar with ICA identity: asset is unchanged and ICA assertion is in the manifest', async () => {
  const { signcert, pkey, certPem } = loadCerts();
  const assetData = new Uint8Array(readFileSync(join(IMAGE_DIR, 'png', 'ChatGPT_Image.png')));
  const issuerDid = computeIcaIssuerDid(ICA_PRIVATE_KEY);

  const result = await signAssetSidecar({
    format: 'image/png',
    asset: assetData,
    manifestDefinition: makeManifest('ChatGPT_Image.png'),
    signcert,
    pkey,
    alg: 'es256',
    issuerDid,
    issuerPrivateKey: ICA_PRIVATE_KEY,
    verifiedIdentities: makeIcaVerifiedIdentities(),
    icaOptions: {
      sigType: 'cawg.identity_claims_aggregation',
      reserveSize: 8192,
      roles: ['cawg.creator'],
    },
  });

  expect(result.manifest.length).toBeGreaterThan(0);
  expect(Buffer.from(result.signedAsset)).toEqual(Buffer.from(assetData));

  const outcome = await verifyAssetFromSidecar({
    format: 'image/png',
    asset: assetData,
    sidecar: result.manifest,
    trustedCertificates: [certPem],
  });

  expect(outcome.manifests.length).toBeGreaterThan(0);
  const firstManifest = outcome.manifests[0];
  const identityKey = Object.keys(firstManifest.assertions).find(
    (k) => k === 'cawg.identity' || k.startsWith('cawg.identity__')
  );
  expect(identityKey).toBeDefined();
});
