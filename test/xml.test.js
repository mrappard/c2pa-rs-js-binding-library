import { expect, test } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import { signXmlAsset, verifyXmlAsset } from '../src/index';

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

const SAMPLE_XML = `<?xml version="1.0" encoding="UTF-8"?>
<settings>
  <enabled>true</enabled>
</settings>
`;

test('sign and verify an XML asset', async () => {
  const { signcert, pkey, certPem } = loadCerts();

  const result = await signXmlAsset(
    SAMPLE_XML,
    makeManifest('settings.xml'),
    signcert,
    pkey,
    'es256'
  );

  expect(result.signedAsset).toBeDefined();
  expect(result.manifest).toBeDefined();

  const signedText = new TextDecoder().decode(result.signedAsset);
  expect(signedText).toContain('BEGIN C2PA MANIFEST');
  expect(signedText.startsWith('<?xml version="1.0" encoding="UTF-8"?>')).toBe(true);

  const outcome = await verifyXmlAsset(result.signedAsset, [certPem]);
  expect(outcome.manifests.length).toBeGreaterThan(0);

  const store = outcome.manifestStore;
  const activeManifest = store.manifests[store.active_manifest];
  expect(activeManifest.claim_generator_info[0].name).toBe('test_generator');
});
