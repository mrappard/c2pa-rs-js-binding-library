import { expect, test } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import {
  signMarkdownAsset,
  verifyMarkdownAsset,
  signAssetWithParentIngredient,
} from '../src/index';

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

const PARENT_MD = `# Source Document\n\nThis is the original source document.\n`;
const CHILD_MD  = `# Derived Document\n\nThis document was derived from the source document.\n`;

test('sign a Markdown file and use it as a parent ingredient in another Markdown file', async () => {
  const { signcert, pkey, certPem } = loadCerts();

  // Step 1: sign the parent Markdown document.
  const parentResult = await signMarkdownAsset(
    PARENT_MD,
    makeManifest('source.md'),
    signcert,
    pkey,
    'es256'
  );
  expect(parentResult.signedAsset).toBeDefined();

  // Step 2: sign the child, embedding the signed parent as a parentOf ingredient.
  const childResult = await signAssetWithParentIngredient(
    'md',
    parentResult.signedAsset,        // child asset body (contains the embedded parent manifest)
    makeManifest('derived.md'),
    signcert,
    pkey,
    'es256',
    'md',                             // parent format
    parentResult.signedAsset,         // parent bytes — manifest is extracted from here
    'source.md'                       // displayed title for the ingredient
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

  const parentResult = await signMarkdownAsset(
    PARENT_MD,
    makeManifest('source.md'),
    signcert,
    pkey,
    'es256'
  );

  const childResult = await signAssetWithParentIngredient(
    'md',
    parentResult.signedAsset,
    makeManifest('derived.md'),
    signcert,
    pkey,
    'es256',
    'md',
    parentResult.signedAsset,
    'source.md'
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
  const gp = await signMarkdownAsset(
    '# Grandparent\n',
    makeManifest('grandparent.md'),
    signcert, pkey, 'es256'
  );

  // Level 2 — parent uses grandparent as ingredient
  const parent = await signAssetWithParentIngredient(
    'md', gp.signedAsset, makeManifest('parent.md'),
    signcert, pkey, 'es256',
    'md', gp.signedAsset, 'grandparent.md'
  );

  // Level 3 — child uses parent as ingredient
  const child = await signAssetWithParentIngredient(
    'md', parent.signedAsset, makeManifest('child.md'),
    signcert, pkey, 'es256',
    'md', parent.signedAsset, 'parent.md'
  );

  const outcome = await verifyMarkdownAsset(child.signedAsset, [certPem]);
  const store = outcome.manifestStore;

  // All three manifests should be present.
  expect(Object.keys(store.manifests).length).toBeGreaterThanOrEqual(3);
  expect(store.manifests[store.activeManifest].title).toBe('child.md');
});
