import { readFileSync, writeFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { signAssetWithCawgMetadata, verifyMarkdownAsset } from '../../src/index.ts';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, '..', '..');

const SAMPLE_DIR = join(root, 'test/assets/sample');
const signcert = new Uint8Array(readFileSync(join(SAMPLE_DIR, 'es256_certs.pem')));
const pkey = new Uint8Array(readFileSync(join(SAMPLE_DIR, 'es256_private.key')));
const certPem = readFileSync(join(SAMPLE_DIR, 'es256_certs.pem'), 'utf-8');

async function run() {
  const unsigned = new Uint8Array(readFileSync(join(__dirname, 'Unsigned-SKILL.md')));

  const manifestDefinition = {
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

  const cawgMetadata = {
    '@context': { dc: 'http://purl.org/dc/elements/1.1/' },
    'dc:creator': 'Matthew Rappard',
    'dc:identifier': 'https://github.com/mrappard',
  };

  const result = await signAssetWithCawgMetadata(
    'md', unsigned, manifestDefinition, cawgMetadata, signcert, pkey, 'es256'
  );

  const outPath = join(__dirname, 'Embedded-SKILL.md');
  writeFileSync(outPath, result.signedAsset);
  console.log(`Embedded-signed markdown written: ${outPath} (${result.signedAsset.length} bytes)`);

  const signedText = new TextDecoder().decode(result.signedAsset);
  console.log('\nEmbedded reference line (truncated):');
  console.log(signedText.split('\n')[0].slice(0, 120) + '...');

  const outcome = await verifyMarkdownAsset(result.signedAsset, [certPem]);
  console.log(`\nverifyMarkdownAsset -> state: ${outcome.state}, manifests: ${outcome.manifests.length}`);
}

run().catch((err) => {
  console.error('Error:', err);
  process.exit(1);
});
