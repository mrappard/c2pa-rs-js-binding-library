import { expect, test } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import { signAsset, verifyAsset } from '../src/index';

const SAMPLE_DIR = join(__dirname, 'assets/sample');
const AUDIO_DIR = join(__dirname, 'assets/audio');

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

test('sign and verify an MP3 asset', async () => {
  const { signcert, pkey, certPem } = loadCerts();
  const asset = new Uint8Array(readFileSync(join(AUDIO_DIR, 'sample1.mp3')));

  const result = await signAsset({ format: 'audio/mpeg', asset, manifestDefinition: makeManifest('sample1.mp3'), signcert, pkey, alg: 'es256' });
  expect(result.signedAsset).toBeDefined();
  expect(result.manifest).toBeDefined();

  const outcome = await verifyAsset('audio/mpeg', result.signedAsset, [certPem]);
  expect(outcome.manifests.length).toBeGreaterThan(0);
  expect(outcome.state).toBe(true);
});

test('sign and verify a WAV asset', async () => {
  const { signcert, pkey, certPem } = loadCerts();
  const asset = new Uint8Array(readFileSync(join(AUDIO_DIR, 'sample1.wav')));

  const result = await signAsset({ format: 'audio/wav', asset, manifestDefinition: makeManifest('sample1.wav'), signcert, pkey, alg: 'es256' });
  expect(result.signedAsset).toBeDefined();
  expect(result.manifest).toBeDefined();

  const outcome = await verifyAsset('audio/wav', result.signedAsset, [certPem]);
  expect(outcome.manifests.length).toBeGreaterThan(0);
  expect(outcome.state).toBe(true);
});

test('sign and verify a FLAC asset', async () => {
  const { signcert, pkey, certPem } = loadCerts();
  const asset = new Uint8Array(readFileSync(join(AUDIO_DIR, 'sample1.flac')));

  const result = await signAsset({ format: 'audio/flac', asset, manifestDefinition: makeManifest('sample1.flac'), signcert, pkey, alg: 'es256' });
  expect(result.signedAsset).toBeDefined();
  expect(result.manifest).toBeDefined();

  const outcome = await verifyAsset('audio/flac', result.signedAsset, [certPem]);
  expect(outcome.manifests.length).toBeGreaterThan(0);
  expect(outcome.state).toBe(true);
});
