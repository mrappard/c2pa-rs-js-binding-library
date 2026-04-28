import { expect, test } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import { signMarkdownAsset, verifyMarkdownAsset, cleanMarkdownAsset } from '../src/index';

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

const SAMPLE_MD = `# Hello World

This is a **Markdown** document with some content.

- Item one
- Item two

> A blockquote for good measure.
`;

test('sign and verify a Markdown asset', async () => {
  const { signcert, pkey, certPem } = loadCerts();

  const result = await signMarkdownAsset(
    SAMPLE_MD,
    makeManifest('hello.md'),
    signcert,
    pkey,
    'es256'
  );

  expect(result.signedAsset).toBeDefined();
  expect(result.manifest).toBeDefined();

  const signedText = new TextDecoder().decode(result.signedAsset);
  expect(signedText).toContain('BEGIN C2PA MANIFEST');
  expect(signedText).toContain('# Hello World');

  const outcome = await verifyMarkdownAsset(result.signedAsset, [certPem]);
  expect(outcome.manifests.length).toBeGreaterThan(0);

  // Check the first manifest in the array
  const firstManifest = outcome.manifests[0];
  
  // Verify claimGeneratorInfo is present and correct (the main requirement)
  expect(firstManifest.claimGeneratorInfo).toBeDefined();
  expect(firstManifest.claimGeneratorInfo).not.toBeNull();
  expect(firstManifest.claimGeneratorInfo[0].name).toBe('test_generator');

  // Verify claimGenerator (can be null in v2, but must be defined)
  expect(firstManifest.claimGenerator !== undefined).toBe(true);
  if (firstManifest.claimGenerator !== null) {
    expect(typeof firstManifest.claimGenerator).toBe('string');
  }
  
  const store = outcome.manifestStore;
  const activeManifest = store.manifests[store.activeManifest];
  expect(activeManifest.title).toBe('hello.md');
  
  // Verify claimGeneratorInfo in the manifest store
  expect(activeManifest.claimGeneratorInfo).toBeDefined();
  expect(activeManifest.claimGeneratorInfo).not.toBeNull();
  expect(activeManifest.claimGeneratorInfo[0].name).toBe('test_generator');

  // Verify claimGenerator in the manifest store
  expect(activeManifest.claimGenerator !== undefined).toBe(true);
  if (activeManifest.claimGenerator !== null) {
    expect(typeof activeManifest.claimGenerator).toBe('string');
  }
});

test('clean a signed Markdown asset removes the C2PA manifest', async () => {
  const { signcert, pkey } = loadCerts();

  const result = await signMarkdownAsset(
    SAMPLE_MD,
    makeManifest('hello.md'),
    signcert,
    pkey,
    'es256'
  );

  const cleaned = cleanMarkdownAsset(result.signedAsset);
  const cleanedText = new TextDecoder().decode(cleaned);
  expect(cleanedText).not.toContain('BEGIN C2PA MANIFEST');
  expect(cleanedText).toContain('# Hello World');
});

test('sign a Markdown asset passed as a string', async () => {
  const { signcert, pkey, certPem } = loadCerts();

  const result = await signMarkdownAsset(
    SAMPLE_MD,
    makeManifest('string-input.md'),
    signcert,
    pkey,
    'es256'
  );

  const outcome = await verifyMarkdownAsset(result.signedAsset, [certPem]);
  expect(outcome.manifests.length).toBeGreaterThan(0);
});
