import { expect, test } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import { addCawgMetadataAssertion, signAssetWithCawgMetadata, verifyAsset } from '../src/index';

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

function getAssertionValue(assertions, label) {
  if (assertions instanceof Map) {
    return assertions.get(label);
  }

  return assertions?.[label];
}

const SAMPLE_CAWG_METADATA = {
  '@context': {
    dc: 'http://purl.org/dc/elements/1.1/',
    photoshop: 'http://ns.adobe.com/photoshop/1.0/',
    Iptc4xmpExt: 'http://iptc.org/std/Iptc4xmpExt/2008-02-29/',
  },
  'dc:title': ['ChatGPT Image'],
  'photoshop:DateCreated': 'Apr 24, 2026',
  'Iptc4xmpExt:PersonInImage': ['Erika Fictional'],
};

test('addCawgMetadataAssertion appends a cawg.metadata assertion', () => {
  const manifest = makeManifest('ChatGPT_Image.png');
  const updatedManifest = addCawgMetadataAssertion(manifest, SAMPLE_CAWG_METADATA);

  expect(updatedManifest).not.toBe(manifest);
  expect(updatedManifest.assertions).toHaveLength(2);
  expect(updatedManifest.assertions[0].label).toBe('c2pa.actions');
  expect(updatedManifest.assertions[1]).toEqual({
    label: 'cawg.metadata',
    data: SAMPLE_CAWG_METADATA,
  });
  expect(manifest.assertions).toHaveLength(1);
});

test('addCawgMetadataAssertion rejects invalid metadata without @context', () => {
  expect(() =>
    addCawgMetadataAssertion(makeManifest('ChatGPT_Image.png'), {
      'dc:title': ['Missing context'],
    })
  ).toThrow(/"@context" must be an object/);
});

test('sign and verify an asset with cawg.metadata', async () => {
  const { signcert, pkey, certPem } = loadCerts();
  const assetData = new Uint8Array(readFileSync(join(IMAGE_DIR, 'png', 'ChatGPT_Image.png')));

  const result = await signAssetWithCawgMetadata(
    'image/png',
    assetData,
    makeManifest('ChatGPT_Image.png'),
    SAMPLE_CAWG_METADATA,
    signcert,
    pkey,
    'es256'
  );

  const outcome = await verifyAsset('image/png', result.signedAsset, [certPem]);
  expect(outcome.manifests.length).toBeGreaterThan(0);

  const activeManifest = outcome.manifests[0];
  const metadataAssertion = getAssertionValue(activeManifest.assertions, 'cawg.metadata');

  expect(metadataAssertion).toBeDefined();
  expect(metadataAssertion['dc:title']).toEqual(['ChatGPT Image']);
  expect(metadataAssertion['photoshop:DateCreated']).toBe('Apr 24, 2026');
  expect(metadataAssertion['@context'].Iptc4xmpExt).toBe(
    'http://iptc.org/std/Iptc4xmpExt/2008-02-29/'
  );
});
