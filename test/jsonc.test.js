import { expect, test } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import { parseJsonc, signJsoncAsset, verifyJsoncAsset } from '../src/index';

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

const SAMPLE_JSONC = `{
  // JSONC keeps user comments
  "name": "settings",
  "enabled": true,
  "items": [
    "alpha",
    "beta",
  ],
}`;

test('parseJsonc parses comments and trailing commas', () => {
  const parsed = parseJsonc(SAMPLE_JSONC);

  expect(parsed).toEqual({
    name: 'settings',
    enabled: true,
    items: ['alpha', 'beta'],
  });
});

test('parseJsonc rejects invalid JSONC', () => {
  expect(() => parseJsonc('{ invalid jsonc }')).toThrow(/Invalid JSONC asset/);
});

test('sign and verify a JSONC asset', async () => {
  const { signcert, pkey, certPem } = loadCerts();

  const result = await signJsoncAsset(
    SAMPLE_JSONC,
    makeManifest('settings.jsonc'),
    signcert,
    pkey,
    'es256'
  );

  expect(result.signedAsset).toBeDefined();
  expect(result.manifest).toBeDefined();

  const signedText = new TextDecoder().decode(result.signedAsset);
  expect(signedText).toContain('BEGIN C2PA MANIFEST');

  const parsedSignedAsset = parseJsonc(signedText);
  expect(parsedSignedAsset.name).toBe('settings');

  const outcome = await verifyJsoncAsset(result.signedAsset, [certPem]);
  expect(outcome.manifests.length).toBeGreaterThan(0);

  const store = outcome.manifestStore;
  const activeManifest = store.manifests[store.active_manifest];
  expect(activeManifest.claim_generator_info[0].name).toBe('test_generator');
});
