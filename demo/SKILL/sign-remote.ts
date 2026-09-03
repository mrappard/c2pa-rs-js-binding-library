import { readFileSync, writeFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { signAssetRemote, verifyAssetFromSidecar, verifyManifestBytes, addCawgMetadataAssertion } from '../../src/index.ts';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, '..', '..');

const REMOTE_URL = 'http://viewer.cognitive-proof.com/manifests/example1';

const SAMPLE_DIR = join(root, 'test/assets/sample');
const signcert = new Uint8Array(readFileSync(join(SAMPLE_DIR, 'es256_certs.pem')));
const pkey = new Uint8Array(readFileSync(join(SAMPLE_DIR, 'es256_private.key')));
const certPem = readFileSync(join(SAMPLE_DIR, 'es256_certs.pem'), 'utf-8');

async function run() {
  const unsigned = readFileSync(join(__dirname, 'Unsigned-SKILL.md'), 'utf-8');

  const baseManifest = {
    claim_generator_info: [{ name: 'c2pa-rs-javascript-library-demo' }],
    title: 'Roger Roger Skill Test',
    assertions: [
      {
        label: 'c2pa.actions',
        data: {
          actions: [
            { action: 'c2pa.created', digitalSourceType: 'http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture' },
          ],
        },
      },
    ],
  };

  const manifestDefinition = addCawgMetadataAssertion(baseManifest, {
    '@context': { dc: 'http://purl.org/dc/elements/1.1/' },
    'dc:creator': 'Matthew Rappard',
    'dc:identifier': 'https://github.com/mrappard',
  });

  const result = await signAssetRemote({
    format: 'md',
    asset: unsigned,
    manifestDefinition,
    signcert,
    pkey,
    alg: 'es256',
    remoteUrl: REMOTE_URL,
  });

  const signedMdPath = join(__dirname, 'SKILL.md');
  writeFileSync(signedMdPath, result.signedAsset);
  console.log(`Signed markdown written: ${signedMdPath} (${result.signedAsset.length} bytes)`);

  const sidecarPath = join(__dirname, 'example1.c2pa');
  writeFileSync(sidecarPath, result.manifest);
  console.log(`Sidecar manifest written: ${sidecarPath} (${result.manifest.length} bytes)`);
  console.log(`  -> host this file's bytes at: ${REMOTE_URL}`);

  const signedText = new TextDecoder().decode(result.signedAsset);
  console.log('\nEmbedded reference line:');
  console.log(signedText.split('\n')[0]);

  // Sanity-check: the sidecar validates against the signed asset bytes and the test cert.
  const outcome = await verifyAssetFromSidecar({
    format: 'md',
    asset: result.signedAsset,
    sidecar: result.manifest,
    trustedCertificates: [certPem],
  });
  console.log(`\nverifyAssetFromSidecar -> state: ${outcome.state}`);

  const manifestOnly = await verifyManifestBytes(result.manifest, [certPem]);
  console.log(`verifyManifestBytes    -> signatureValid: ${manifestOnly.signatureValid}, trusted: ${manifestOnly.trusted}`);
}

run().catch((err) => {
  console.error('Error:', err);
  process.exit(1);
});
