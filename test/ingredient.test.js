import { expect, test } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import {
  verifyMarkdownAsset,
  signAsset,
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
  const childResult = await signAsset({
    format: 'md',
    asset: parentResult.signedAsset,
    manifestDefinition: makeManifest('derived.md'),
    signcert,
    pkey,
    alg: 'es256',
    parentFormat: 'md',
    parentAsset: parentResult.signedAsset,
    parentTitle: 'source.md',
  });

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

  const childResult = await signAsset({
    format: 'md',
    asset: parentResult.signedAsset,
    manifestDefinition: makeManifest('derived.md'),
    signcert,
    pkey,
    alg: 'es256',
    parentFormat: 'md',
    parentAsset: parentResult.signedAsset,
    parentTitle: 'source.md',
  });

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
  const parent = await signAsset({
    format: 'md', asset: gp.signedAsset, manifestDefinition: makeManifest('parent.md'),
    signcert, pkey, alg: 'es256',
    parentFormat: 'md', parentAsset: gp.signedAsset, parentTitle: 'grandparent.md',
  });

  // Level 3 — child uses parent as ingredient
  const child = await signAsset({
    format: 'md', asset: parent.signedAsset, manifestDefinition: makeManifest('child.md'),
    signcert, pkey, alg: 'es256',
    parentFormat: 'md', parentAsset: parent.signedAsset, parentTitle: 'parent.md',
  });

  const outcome = await verifyMarkdownAsset(child.signedAsset, [certPem]);
  const store = outcome.manifestStore;

  // All three manifests should be present.
  expect(Object.keys(store.manifests).length).toBeGreaterThanOrEqual(3);
  expect(store.manifests[store.activeManifest].title).toBe('child.md');
});
