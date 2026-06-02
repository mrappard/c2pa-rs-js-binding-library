import { expect, test } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import { getResource } from '../src/index';

const IMAGE_DIR = join(__dirname, 'assets/image/good/png');

const ICON_URI = 'self#jumbf=-c2pa-urn-c2pa-2637aa41-996a-4e42-8797-24377ebae34e-c2pa.assertions-c2pa.icon';

test('extract icon resource from ChatGPT_Image_With_Icon.png', async () => {
  const assetBytes = new Uint8Array(readFileSync(join(IMAGE_DIR, 'ChatGPT_Image_With_Icon.png')));

  const iconBytes = await getResource('image/png', assetBytes, ICON_URI);

  expect(iconBytes).toBeDefined();
  expect(iconBytes.length).toBeGreaterThan(0);

  // The icon is SVG — confirm it starts with SVG markup
  const text = new TextDecoder().decode(iconBytes);
  expect(text.trim().startsWith('<svg') || text.trim().startsWith('<?xml')).toBe(true);
});
