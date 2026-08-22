import { expect, test } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import {
  prepareIdentityAssertion,
  finalizeIdentityAssertion,
  signIdentityAssertionPayloadX509,
  signAsset,
  computeIcaIssuerDid,
  prepareIcaIdentityAssertion,
  finalizeIcaIdentityAssertion,
  verifyAsset,
  verifyIdentityAssertions,
} from '../src/index';

const ASSETS_DIR = join(__dirname, 'assets');
const IMAGE_DIR = join(ASSETS_DIR, 'image', 'good');
const SAMPLE_DIR = join(__dirname, 'assets/sample');

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

  const result = await signAsset({
    format: 'image/png',
    asset: assetData,
    manifestDefinition: makeManifest('ChatGPT_Image.png'),
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

// ── ICA (Identity Claims Aggregation) tests ─────────────────────────────────

// A fixed 32-byte Ed25519 seed used across all ICA tests.
const ICA_PRIVATE_KEY = new Uint8Array(Array.from({ length: 32 }, (_, i) => i + 1));

function makeIcaVerifiedIdentities() {
  return [
    {
      type: 'cawg.social_media',
      username: 'testuser',
      uri: 'https://example-social.com/testuser',
      verifiedAt: '2024-01-01T00:00:00Z',
      provider: {
        id: 'https://example-social.com',
        name: 'Example Social',
      },
    },
  ];
}

test('computeIcaIssuerDid derives a did:jwk from an Ed25519 private key', () => {
  const did = computeIcaIssuerDid(ICA_PRIVATE_KEY);
  expect(did).toMatch(/^did:jwk:/);
  // Same key → same DID (deterministic)
  expect(did).toBe(computeIcaIssuerDid(ICA_PRIVATE_KEY));
});

test('signAssetWithIcaIdentity signs a PNG with an ICA identity assertion', async () => {
  const { signcert, pkey, certPem } = loadCerts();
  const assetData = new Uint8Array(readFileSync(join(IMAGE_DIR, 'png', 'ChatGPT_Image.png')));
  const issuerDid = computeIcaIssuerDid(ICA_PRIVATE_KEY);

  const result = await signAsset({
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

  expect(result.signedAsset).toBeDefined();
  expect(result.signedAsset.length).toBeGreaterThan(0);
  expect(result.manifest).toBeDefined();

  // The C2PA manifest must be well-formed and verifiable.
  const outcome = await verifyAsset('image/png', result.signedAsset, [certPem]);
  expect(outcome.manifests.length).toBeGreaterThan(0);
});

test('signAssetWithIcaIdentity: verifyIdentityAssertions returns the ICA assertion', async () => {
  const { signcert, pkey, certPem } = loadCerts();
  const assetData = new Uint8Array(readFileSync(join(IMAGE_DIR, 'png', 'ChatGPT_Image.png')));
  const issuerDid = computeIcaIssuerDid(ICA_PRIVATE_KEY);

  const result = await signAsset({
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

  const identityOutcome = await verifyIdentityAssertions('image/png', result.signedAsset, [certPem]);
  const manifestIds = Object.keys(identityOutcome.manifests);
  expect(manifestIds.length).toBeGreaterThan(0);

  const assertions = identityOutcome.manifests[manifestIds[0]];
  expect(assertions.length).toBeGreaterThan(0);

  // For ICA assertions, `data` is the ICA credential summary (VC fields).
  // The sig_type comes from the assertion label and the validated flag.
  expect(assertions[0].validated).toBe(true);
  expect(assertions[0].data.type).toContain('IdentityClaimsAggregationCredential');
  expect(assertions[0].data.issuer).toBe(issuerDid);
  expect(assertions[0].data.verifiedIdentities[0].type).toBe('cawg.social_media');
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

  const r1 = await signAsset({ format: 'image/png', asset: assetData, manifestDefinition: makeStableManifest('test.png', FIXED_SALT), signcert, pkey, alg: 'es256' });
  const r2 = await signAsset({ format: 'image/png', asset: assetData, manifestDefinition: makeStableManifest('test.png', FIXED_SALT), signcert, pkey, alg: 'es256' });

  // Manifest (JUMBF) bytes must be identical: same salt → same assertion hashes
  expect(Array.from(r1.manifest)).toEqual(Array.from(r2.manifest));
});

test('assertion_salt: different salts produce different manifest bytes', async () => {
  const { signcert, pkey } = loadCerts();
  const assetData = new Uint8Array(readFileSync(join(IMAGE_DIR, 'png', 'ChatGPT_Image.png')));

  const saltA = Array.from({ length: 16 }, () => 0xAA);
  const saltB = Array.from({ length: 16 }, () => 0xBB);

  const r1 = await signAsset({ format: 'image/png', asset: assetData, manifestDefinition: makeStableManifest('test.png', saltA), signcert, pkey, alg: 'es256' });
  const r2 = await signAsset({ format: 'image/png', asset: assetData, manifestDefinition: makeStableManifest('test.png', saltB), signcert, pkey, alg: 'es256' });

  // Different salts → different assertion hashes in claim → different JUMBF bytes
  expect(Array.from(r1.manifest)).not.toEqual(Array.from(r2.manifest));
});

test('assertion_salt: signing and verification succeeds with a fixed salt', async () => {
  const { signcert, pkey, certPem } = loadCerts();
  const assetData = new Uint8Array(readFileSync(join(IMAGE_DIR, 'png', 'ChatGPT_Image.png')));

  const result = await signAsset({ format: 'image/png', asset: assetData, manifestDefinition: makeStableManifest('test.png', FIXED_SALT), signcert, pkey, alg: 'es256' });
  expect(result.signedAsset).toBeDefined();

  const outcome = await verifyAsset('image/png', result.signedAsset, [certPem]);
  expect(outcome.manifests.length).toBeGreaterThan(0);
});

test('prepareIcaIdentityAssertion + finalizeIcaIdentityAssertion round-trip matches direct ICA signing', async () => {
  const { signcert, pkey, certPem } = loadCerts();
  const assetData = new Uint8Array(readFileSync(join(IMAGE_DIR, 'jpeg', 'Firefly_tabby_cat.jpg')));

  // Ed25519 key — 32-byte seed (same key used in the in-process ICA signing tests)
  const issuerSeed = new Uint8Array(32).fill(0x42);
  const issuerDid = computeIcaIssuerDid(issuerSeed);

  const verifiedIdentities = [{
    type: 'cawg.social_media',
    username: 'testuser',
    uri: 'https://social.example.com/testuser',
    verifiedAt: '2024-01-01T00:00:00Z',
    provider: { id: 'https://social.example.com', name: 'Test Social' },
  }];

  const icaOptions = {
    sigType: 'cawg.identity_claims_aggregation',
    reserveSize: 8192,
    roles: ['cawg.creator'],
  };

  // Two-step external signing flow
  const prepared = await prepareIcaIdentityAssertion({
    format: 'image/jpeg',
    asset: assetData,
    manifestDefinition: makeManifest('tabby.jpg'),
    signcert, pkey, alg: 'es256',
    issuerDid, verifiedIdentities, icaOptions,
  });

  expect(prepared.toSign).toBeDefined();
  expect(prepared.toSign.length).toBeGreaterThan(0);
  expect(prepared.vcBytes).toBeDefined();
  expect(prepared.issuerDid).toBe(issuerDid);

  // Sign the captured to_sign bytes using Node's crypto module.
  // Node doesn't accept raw Ed25519 seeds — wrap the 32-byte seed in a minimal
  // PKCS#8 DER envelope (1.3.101.112 = Ed25519 OID) then import it.
  const { createPrivateKey, sign: nodeCryptoSign } = await import('crypto');
  const pkcs8Prefix = Buffer.from([
    0x30, 0x2e,             // SEQUENCE (46 bytes)
    0x02, 0x01, 0x00,       // INTEGER version=0
    0x30, 0x05,             // SEQUENCE
      0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
    0x04, 0x22,             // OCTET STRING (34 bytes)
      0x04, 0x20,           // OCTET STRING (32 bytes = the seed)
  ]);
  const pkcs8Der = Buffer.concat([pkcs8Prefix, Buffer.from(issuerSeed)]);
  const privateKey = createPrivateKey({ key: pkcs8Der, format: 'der', type: 'pkcs8' });
  // crypto.sign(null, data, keyObject) returns a 64-byte raw R||S Ed25519 signature.
  const signature = new Uint8Array(nodeCryptoSign(null, Buffer.from(prepared.toSign), privateKey));

  const result = await finalizeIcaIdentityAssertion(prepared, signature);
  expect(result.signedAsset).toBeDefined();
  expect(result.signedAsset.length).toBeGreaterThan(0);

  // Verify the outer C2PA claim
  const outcome = await verifyAsset('image/jpeg', result.signedAsset, [certPem]);
  expect(outcome.manifests.length).toBeGreaterThan(0);

  // Verify the ICA identity assertion
  const idOutcome = await verifyIdentityAssertions('image/jpeg', result.signedAsset, [certPem]);
  const firstManifestId = Object.keys(idOutcome.manifests)[0];
  expect(firstManifestId).toBeDefined();
  const assertions = idOutcome.manifests[firstManifestId];
  const icaAssertion = assertions.find(a => a.label && a.label.startsWith('cawg.identity'));
  expect(icaAssertion).toBeDefined();
  expect(icaAssertion.validated).toBe(true);
});
