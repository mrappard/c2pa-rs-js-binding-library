import { verifyAsset } from '../src/index';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

function mapToObject(value: any): any {
  if (value instanceof Map) {
    return Object.fromEntries(
      Array.from(value.entries()).map(([key, val]) => [
        key,
        mapToObject(val),
      ])
    );
  }

  if (Array.isArray(value)) {
    return value.map(mapToObject);
  }

  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, val]) => [
        key,
        mapToObject(val),
      ])
    );
  }

  return value;
}

async function run() {
  const pngPath = join(__dirname, '../test/assets/image/good/png/ChatGPT_Image.png');
  const buffer = readFileSync(pngPath);
  const assetData = new Uint8Array(buffer);

  try {
    console.log(`Verifying: ${pngPath}`);
    const outcome = await verifyAsset('image/png', assetData, []);
    
    if (outcome.manifests.length === 0) {
      console.log('No manifests found in the image.');
      return;
    }

    console.log('--- Found Manifests ---');
    console.log(JSON.stringify( mapToObject(outcome.manifestStore), null, 2));

  } catch (error) {
    console.error('Error verifying asset:', error);
  }
}

run();
