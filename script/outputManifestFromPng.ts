import { verifyAsset } from '../src/index.ts';
import { readFileSync, readdirSync, writeFileSync } from 'fs';
import { join, dirname, extname, basename } from 'path';
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
  const pngDir = join(__dirname, '../test/assets/image/good/png');
  const outputDir = join(__dirname, 'output');

  const files = readdirSync(pngDir).filter(f => extname(f).toLowerCase() === '.png');

  for (const file of files) {
    const filePath = join(pngDir, file);
    const buffer = readFileSync(filePath);
    const assetData = new Uint8Array(buffer);

    console.log(`Verifying: ${file}`);
    try {
      const outcome = await verifyAsset('image/png', assetData, []);
      const name = basename(file, extname(file));
      const outPath = join(outputDir, `${name}.json`);

      if (outcome.manifests.length === 0) {
        writeFileSync(outPath, JSON.stringify({ manifests: [] }, null, 2));
        console.log(`  No manifests found — wrote ${name}.json`);
        continue;
      }

      writeFileSync(outPath, JSON.stringify(mapToObject(outcome.manifestStore), null, 2));
      console.log(`  Wrote ${name}.json`);
    } catch (error) {
      console.error(`  Error verifying ${file}:`, error);
    }
  }
}

run();
