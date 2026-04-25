import { expect, test } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import {
  prepareIdentityAssertion,
  finalizeIdentityAssertion,
  signIdentityAssertionPayloadX509,
  signAsset,
  signAssetWithX509Identity,
  verifyAsset,
  verifyIdentityAssertions,
} from '../src/index';

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

test('prepareIdentityAssertion returns signer payload for an external signer', async () => {
  const { signcert, pkey, certPem } = loadCerts();
  const assetData = new Uint8Array(readFileSync(join(IMAGE_DIR, 'png', 'ChatGPT_Image.png')));

  const prepared = await prepareIdentityAssertion(
    'image/png',
    assetData,
    makeManifest('ChatGPT_Image.png'),
    signcert,
    pkey,
    'es256',
    {
      sigType: 'cawg.x509.cose',
      reserveSize: 4096,
      referencedAssertions: ['c2pa.actions'],
      roles: ['cawg.creator'],
    }
  );

  expect(prepared.signerPayload.sig_type).toBe('cawg.x509.cose');
  expect(prepared.signerPayload.role).toEqual(['cawg.creator']);
  expect(prepared.signerPayload.referenced_assertions.length).toBeGreaterThan(0);
  expect(prepared.signerPayloadCbor.length).toBeGreaterThan(0);
  expect(prepared.manifestDefinition.instance_id).toBeDefined();
  expect(certPem).toContain('BEGIN CERTIFICATE');
});

test('signAssetWithX509Identity signs and verifies a cawg.identity assertion', async () => {
  const { signcert, pkey, certPem } = loadCerts();
  const assetData = new Uint8Array(readFileSync(join(IMAGE_DIR, 'png', 'ChatGPT_Image.png')));

  const result = await signAssetWithX509Identity(
    'image/png',
    assetData,
    makeManifest('ChatGPT_Image.png'),
    signcert,
    pkey,
    'es256',
    signcert,
    pkey,
    'es256',
    {
      sigType: 'cawg.x509.cose',
      reserveSize: 4096,
      referencedAssertions: ['c2pa.actions'],
      roles: ['cawg.creator'],
    }
  );

  expect(result.signedAsset).toBeDefined();
  expect(result.manifest).toBeDefined();

  const c2paOutcome = await verifyAsset('image/png', result.signedAsset, [certPem]);
  expect(c2paOutcome.manifests.length).toBeGreaterThan(0);

  const identityOutcome = await verifyIdentityAssertions('image/png', result.signedAsset, [certPem]);
  const manifestIds = Object.keys(identityOutcome.manifests);
  expect(manifestIds.length).toBeGreaterThan(0);

  const identityAssertions = identityOutcome.manifests[manifestIds[0]];
  expect(identityAssertions.length).toBeGreaterThan(0);
  expect(identityAssertions[0].validated).toBe(true);
  expect(identityAssertions[0].data.signer_payload.sig_type).toBe('cawg.x509.cose');
  expect(identityAssertions[0].data.signature_info.issuer).toBeDefined();
});


test('finalizeIdentityAssertion completes the two-call external signing flow', async () => {
  const { signcert, pkey, certPem } = loadCerts();
  const assetData = new Uint8Array(readFileSync(join(IMAGE_DIR, 'png', 'ChatGPT_Image.png')));

  const options = {
    sigType: 'cawg.x509.cose',
    reserveSize: 4096,
    referencedAssertions: ['c2pa.actions'],
    roles: ['cawg.creator'],
  };

  // Step 1: prepare — capture the signer payload for the external signer.
  const prepared = await prepareIdentityAssertion(
    'image/png',
    assetData,
    makeManifest('ChatGPT_Image.png'),
    signcert,
    pkey,
    'es256',
    options
  );

  expect(prepared.signerPayloadCbor.length).toBeGreaterThan(0);

  // Step 2: external sign — in production this is done by a wallet / HSM.
  const signature = signIdentityAssertionPayloadX509(
    prepared.signerPayloadCbor,
    signcert,
    pkey,
    'es256',
  );

  expect(signature.length).toBeGreaterThan(0);

  // Step 3: finalize — embed the real signature and produce the signed asset.
  const result = await finalizeIdentityAssertion(prepared, signature);

  expect(result.signedAsset).toBeDefined();
  expect(result.manifest).toBeDefined();

  // Verify the C2PA manifest is valid.
  const c2paOutcome = await verifyAsset('image/png', result.signedAsset, [certPem]);
  expect(c2paOutcome.manifests.length).toBeGreaterThan(0);

  // Verify the identity assertion was correctly embedded and validates.
  const identityOutcome = await verifyIdentityAssertions('image/png', result.signedAsset, [certPem]);
  const manifestIds = Object.keys(identityOutcome.manifests);
  expect(manifestIds.length).toBeGreaterThan(0);

  const identityAssertions = identityOutcome.manifests[manifestIds[0]];
  expect(identityAssertions.length).toBeGreaterThan(0);
  expect(identityAssertions[0].validated).toBe(true);
  expect(identityAssertions[0].data.signer_payload.sig_type).toBe('cawg.x509.cose');
  expect(identityAssertions[0].data.signature_info.issuer).toBeDefined();
});

// ── assertion_salt tests ─────────────────────────────────────────────────────
//
// assertion_salt affects the JUMBF claim's assertion HashedURIs (the hash of
// each assertion box includes the salt). It does NOT feed into
// signer_payload.referenced_assertions (those URIs come from the hard-binding
// c2pa.hash.data assertion, which uses DefaultSalt::default() independently).
// The right observable is therefore the manifest (JUMBF) bytes.

const FIXED_SALT = Array.from({ length: 16 }, (_, i) => i + 1); // [1..16]
// Stable IDs so both signing calls produce the same JUMBF when the salt matches
const STABLE_INSTANCE_ID = 'xmp:iid:aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa';
const STABLE_LABEL       = 'urn:c2pa:bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb';

function makeStableManifest(title, salt) {
  const m = {
    ...makeManifest(title),
    instance_id: STABLE_INSTANCE_ID,
    label: STABLE_LABEL,
  };
  if (salt !== undefined) m.assertion_salt = salt;
  return m;
}

test('assertion_salt: same salt produces identical manifest bytes', async () => {
  const { signcert, pkey } = loadCerts();
  const assetData = new Uint8Array(readFileSync(join(IMAGE_DIR, 'png', 'ChatGPT_Image.png')));

  const r1 = await signAsset('image/png', assetData, makeStableManifest('test.png', FIXED_SALT), signcert, pkey, 'es256');
  const r2 = await signAsset('image/png', assetData, makeStableManifest('test.png', FIXED_SALT), signcert, pkey, 'es256');

  // Manifest (JUMBF) bytes must be identical: same salt → same assertion hashes
  expect(Array.from(r1.manifest)).toEqual(Array.from(r2.manifest));
});

test('assertion_salt: different salts produce different manifest bytes', async () => {
  const { signcert, pkey } = loadCerts();
  const assetData = new Uint8Array(readFileSync(join(IMAGE_DIR, 'png', 'ChatGPT_Image.png')));

  const saltA = Array.from({ length: 16 }, () => 0xAA);
  const saltB = Array.from({ length: 16 }, () => 0xBB);

  const r1 = await signAsset('image/png', assetData, makeStableManifest('test.png', saltA), signcert, pkey, 'es256');
  const r2 = await signAsset('image/png', assetData, makeStableManifest('test.png', saltB), signcert, pkey, 'es256');

  // Different salts → different assertion hashes in claim → different JUMBF bytes
  expect(Array.from(r1.manifest)).not.toEqual(Array.from(r2.manifest));
});

test('assertion_salt: signing and verification succeeds with a fixed salt', async () => {
  const { signcert, pkey, certPem } = loadCerts();
  const assetData = new Uint8Array(readFileSync(join(IMAGE_DIR, 'png', 'ChatGPT_Image.png')));

  const result = await signAsset('image/png', assetData, makeStableManifest('test.png', FIXED_SALT), signcert, pkey, 'es256');
  expect(result.signedAsset).toBeDefined();

  const outcome = await verifyAsset('image/png', result.signedAsset, [certPem]);
  expect(outcome.manifests.length).toBeGreaterThan(0);
});
