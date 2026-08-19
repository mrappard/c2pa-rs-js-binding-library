import { expect, test } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import {
  verifyMarkdownAsset,
  signAsset,
  signAssetSidecar,
  signAssetWithIngredients,
  verifyAsset,
} from '../src/index';

const SAMPLE_DIR = join(__dirname, 'assets/sample');
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
    assertions: [{ label: 'c2pa.actions', data: { actions: [{ action: 'c2pa.created', digitalSourceType: 'http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture' }] } }],
  };
}

const PARENT_MD = `# Source Document\n\nThis is the original source document.\n`;
const CHILD_MD  = `# Derived Document\n\nThis document was derived from the source document.\n`;

test('sign a Markdown file and use it as a parent ingredient in another Markdown file', async () => {
  const { signcert, pkey, certPem } = loadCerts();

  // Step 1: sign the parent Markdown document.
  const parentResult = await signAsset({
    format: 'md',
    asset: PARENT_MD,
    manifestDefinition: makeManifest('source.md'),
    signcert,
    pkey,
    alg: 'es256',
  });
  expect(parentResult.signedAsset).toBeDefined();

  // Step 2: sign the child, embedding the signed parent as a parentOf ingredient.
  const childResult = await signAssetWithIngredients(
    'md',
    parentResult.signedAsset,
    makeManifest('derived.md'),
    signcert,
    pkey,
    'es256',
    [{ format: 'md', asset: parentResult.signedAsset, title: 'source.md', relationship: 'parentOf' }]
  );

  expect(childResult.signedAsset).toBeDefined();
  expect(childResult.manifest).toBeDefined();

  // Step 3: verify the child manifest.
  const outcome = await verifyMarkdownAsset(childResult.signedAsset, [certPem]);
  expect(outcome.manifests.length).toBeGreaterThan(0);

  // The active manifest is the child's — use manifestStore to locate it.
  const store = outcome.manifestStore;
  const childManifest = outcome.manifests.find(m => m.id === store.activeManifest);
  expect(childManifest).toBeDefined();
  expect(childManifest.title).toBe('derived.md');

  // The child manifest must record the parent as an ingredient.
  expect(childManifest.ingredients.length).toBeGreaterThan(0);
  expect(childManifest.ingredients[0].manifestId).toBeDefined();
});

test('parent and child manifest are both present in the manifest store', async () => {
  const { signcert, pkey, certPem } = loadCerts();

  const parentResult = await signAsset({
    format: 'md',
    asset: PARENT_MD,
    manifestDefinition: makeManifest('source.md'),
    signcert,
    pkey,
    alg: 'es256',
  });

  const childResult = await signAssetWithIngredients(
    'md',
    parentResult.signedAsset,
    makeManifest('derived.md'),
    signcert,
    pkey,
    'es256',
    [{ format: 'md', asset: parentResult.signedAsset, title: 'source.md', relationship: 'parentOf' }]
  );

  const outcome = await verifyMarkdownAsset(childResult.signedAsset, [certPem]);
  const store = outcome.manifestStore;

  // Both the child manifest and the embedded parent manifest are in the store.
  const allIds = Object.keys(store.manifests);
  expect(allIds.length).toBeGreaterThanOrEqual(2);

  // Active manifest is the child.
  expect(store.activeManifest).toBeDefined();
  expect(store.manifests[store.activeManifest].title).toBe('derived.md');

  // The ingredient's manifestId points to the parent entry in the same store.
  const childManifest = outcome.manifests.find(m => m.id === store.activeManifest);
  const parentManifestId = childManifest.ingredients[0].manifestId;
  expect(store.manifests[parentManifestId]).toBeDefined();
  expect(store.manifests[parentManifestId].title).toBe('source.md');
});

test('ingredient chain spans three levels of Markdown documents', async () => {
  const { signcert, pkey, certPem } = loadCerts();

  // Level 1 — grandparent
  const gp = await signAsset({
    format: 'md',
    asset: '# Grandparent\n',
    manifestDefinition: makeManifest('grandparent.md'),
    signcert, pkey, alg: 'es256',
  });

  // Level 2 — parent uses grandparent as ingredient
  const parent = await signAssetWithIngredients(
    'md', gp.signedAsset, makeManifest('parent.md'), signcert, pkey, 'es256',
    [{ format: 'md', asset: gp.signedAsset, title: 'grandparent.md', relationship: 'parentOf' }]
  );

  // Level 3 — child uses parent as ingredient
  const child = await signAssetWithIngredients(
    'md', parent.signedAsset, makeManifest('child.md'), signcert, pkey, 'es256',
    [{ format: 'md', asset: parent.signedAsset, title: 'parent.md', relationship: 'parentOf' }]
  );

  const outcome = await verifyMarkdownAsset(child.signedAsset, [certPem]);
  const store = outcome.manifestStore;

  // All three manifests should be present.
  expect(Object.keys(store.manifests).length).toBeGreaterThanOrEqual(3);
  expect(store.manifests[store.activeManifest].title).toBe('child.md');
});

// ── Sidecar ingredient tests ──────────────────────────────────────────────────

test('sidecar-backed asset can be used as a parent ingredient', async () => {
  const { signcert, pkey, certPem } = loadCerts();
  const sourceData = new Uint8Array(readFileSync(join(IMAGE_DIR, 'jpeg', 'Firefly_tabby_cat.jpg')));
  const derivedData = new Uint8Array(readFileSync(join(IMAGE_DIR, 'png', 'ChatGPT_Image.png')));

  // Step 1: sign the source asset with a sidecar manifest.
  const sidecarResult = await signAssetSidecar({
    format: 'image/jpeg',
    asset: sourceData,
    manifestDefinition: makeManifest('source.jpg'),
    signcert,
    pkey,
    alg: 'es256',
  });

  // The sidecar asset is unchanged; the manifest is a separate buffer.
  expect(sidecarResult.manifest.length).toBeGreaterThan(0);

  // Step 2: sign the derived asset, referencing the sidecar-backed source as a parent ingredient.
  const childResult = await signAssetWithIngredients(
    'image/png',
    derivedData,
    makeManifest('derived.png'),
    signcert,
    pkey,
    'es256',
    [{
      format: 'image/jpeg',
      asset: sidecarResult.signedAsset,
      title: 'source.jpg',
      relationship: 'parentOf',
      sidecar: sidecarResult.manifest,
    }]
  );

  expect(childResult.signedAsset).toBeDefined();
  expect(childResult.manifest).toBeDefined();

  // Step 3: verify the child manifest.
  const outcome = await verifyAsset('image/png', childResult.signedAsset, [certPem]);
  expect(outcome.manifests.length).toBeGreaterThan(0);

  const store = outcome.manifestStore;
  const childManifest = outcome.manifests.find(m => m.id === store.activeManifest);
  expect(childManifest).toBeDefined();
  expect(childManifest.title).toBe('derived.png');

  // The child manifest must record the sidecar-backed source as an ingredient.
  expect(childManifest.ingredients.length).toBeGreaterThan(0);
  const ingredient = childManifest.ingredients[0];
  expect(ingredient.title).toBe('source.jpg');
  // The ingredient's manifestId links it to the source's embedded manifest data.
  expect(ingredient.manifestId).toBeDefined();
});

test('sidecar ingredient manifest data is embedded in the child claim', async () => {
  const { signcert, pkey, certPem } = loadCerts();
  const sourceData = new Uint8Array(readFileSync(join(IMAGE_DIR, 'jpeg', 'Firefly_tabby_cat.jpg')));
  const derivedData = new Uint8Array(readFileSync(join(IMAGE_DIR, 'png', 'ChatGPT_Image.png')));

  const sidecarResult = await signAssetSidecar({
    format: 'image/jpeg',
    asset: sourceData,
    manifestDefinition: makeManifest('source.jpg'),
    signcert,
    pkey,
    alg: 'es256',
  });

  const childResult = await signAssetWithIngredients(
    'image/png',
    derivedData,
    makeManifest('derived.png'),
    signcert,
    pkey,
    'es256',
    [{
      format: 'image/jpeg',
      asset: sidecarResult.signedAsset,
      title: 'source.jpg',
      relationship: 'parentOf',
      sidecar: sidecarResult.manifest,
    }]
  );

  const outcome = await verifyAsset('image/png', childResult.signedAsset, [certPem]);
  const store = outcome.manifestStore;

  // The manifest store must contain both the child's manifest and the
  // embedded source manifest (carried over from the sidecar bytes).
  const allIds = Object.keys(store.manifests);
  expect(allIds.length).toBeGreaterThanOrEqual(2);

  // The source manifest is accessible by the ingredient's manifestId.
  const childManifest = outcome.manifests.find(m => m.id === store.activeManifest);
  const ingredientManifestId = childManifest.ingredients[0].manifestId;
  expect(store.manifests[ingredientManifestId]).toBeDefined();
  expect(store.manifests[ingredientManifestId].title).toBe('source.jpg');
});
