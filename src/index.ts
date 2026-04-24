import * as wasm from '../pkg/c2pa_rs_wasm.js';
import { parse, printParseErrorCode } from 'jsonc-parser';

export type { SupportedFormat, VerificationOutcome, RecognizedManifest, C2PAThumbnail, C2PAIngredient, SigningAlg } from '../pkg/c2pa_rs_wasm.js';

const JSONC_FORMAT = 'jsonc' as wasm.SupportedFormat;
const JSONC_MANIFEST_PREFIX = '// -----BEGIN C2PA MANIFEST-----';
const JSONC_EMPTY_MANIFEST_BLOCK = `${JSONC_MANIFEST_PREFIX} data:application/c2pa;base64, -----END C2PA MANIFEST-----\n`;
const XML_FORMAT = 'xml' as wasm.SupportedFormat;
const XML_MANIFEST_PREFIX = '<!-- -----BEGIN C2PA MANIFEST-----';
const XML_EMPTY_MANIFEST_BLOCK = `${XML_MANIFEST_PREFIX} data:application/c2pa;base64, -----END C2PA MANIFEST----- -->\n`;
const MD_FORMAT = 'md' as wasm.SupportedFormat;
const MD_MANIFEST_PREFIX = '<!-- -----BEGIN C2PA MANIFEST-----';
const MD_EMPTY_MANIFEST_BLOCK = `${MD_MANIFEST_PREFIX} data:application/c2pa;base64, -----END C2PA MANIFEST----- -->\n`;
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export type JsoncAssetInput = string | Uint8Array;

function decodeJsoncAsset(asset: JsoncAssetInput): string {
  return typeof asset === 'string' ? asset : textDecoder.decode(asset);
}

function encodeJsoncAsset(asset: JsoncAssetInput): Uint8Array {
  return typeof asset === 'string' ? textEncoder.encode(asset) : asset;
}

function assertValidJsoncAsset(asset: JsoncAssetInput): string {
  const text = decodeJsoncAsset(asset);
  const errors = [];

  parse(text, errors, { allowTrailingComma: true, disallowComments: false });

  if (errors.length > 0) {
    const formattedErrors = errors
      .map((error) => `${printParseErrorCode(error.error)} at offset ${error.offset}`)
      .join(', ');
    throw new Error(`Invalid JSONC asset: ${formattedErrors}`);
  }

  return text;
}

function ensureJsoncManifestPlaceholder(asset: JsoncAssetInput): Uint8Array {
  const text = assertValidJsoncAsset(asset);
  const withPlaceholder = text.includes(JSONC_MANIFEST_PREFIX)
    ? text
    : `${JSONC_EMPTY_MANIFEST_BLOCK}${text}`;
  return textEncoder.encode(withPlaceholder);
}

function ensureXmlManifestPlaceholder(asset: JsoncAssetInput): Uint8Array {
  const text = decodeJsoncAsset(asset);

  if (text.includes(XML_MANIFEST_PREFIX)) {
    return textEncoder.encode(text);
  }

  const withPlaceholder = text.startsWith('<?xml')
    ? `${text}${text.endsWith('\n') ? '' : '\n'}${XML_EMPTY_MANIFEST_BLOCK}`
    : `${XML_EMPTY_MANIFEST_BLOCK}${text}`;

  return textEncoder.encode(withPlaceholder);
}

function ensureMarkdownManifestPlaceholder(asset: JsoncAssetInput): Uint8Array {
  const text = decodeJsoncAsset(asset);

  if (text.includes(MD_MANIFEST_PREFIX)) {
    return textEncoder.encode(text);
  }

  return textEncoder.encode(`${MD_EMPTY_MANIFEST_BLOCK}${text}`);
}

/**
 * Calls the Rust hello_world function and returns the result.
 */
export function sayHello(): string {
  return wasm.hello_world();
}

/**
 * Verifies a C2PA asset.
 * 
 * @param format The format of the asset (e.g., 'application/pdf').
 * @param asset The asset bytes as a Uint8Array.
 * @param trustedCertificates An array of trusted certificates in PEM format.
 * @returns A promise that resolves to a VerificationOutcome.
 */
export async function verifyAsset(
  format: wasm.SupportedFormat,
  asset: Uint8Array,
  trustedCertificates: string[]
): Promise<wasm.VerificationOutcome> {
  return wasm.verify_asset(format, asset, trustedCertificates);
}

/**
 * Signs a C2PA asset.
 */
export async function signAsset(
  format: wasm.SupportedFormat,
  asset: Uint8Array,
  manifestDefinition: any,
  signcert: Uint8Array,
  pkey: Uint8Array,
  alg: wasm.SigningAlg,
  tsaUrl?: string
): Promise<wasm.C2PASignResult> {
  return wasm.sign_asset(format, asset, manifestDefinition, signcert, pkey, alg, tsaUrl);
}

export function parseJsonc<T = unknown>(asset: JsoncAssetInput): T {
  const text = assertValidJsoncAsset(asset);
  return parse(text, [], { allowTrailingComma: true, disallowComments: false }) as T;
}

export async function signJsoncAsset(
  asset: JsoncAssetInput,
  manifestDefinition: any,
  signcert: Uint8Array,
  pkey: Uint8Array,
  alg: wasm.SigningAlg,
  tsaUrl?: string
): Promise<wasm.C2PASignResult> {
  return signAsset(
    JSONC_FORMAT,
    ensureJsoncManifestPlaceholder(asset),
    manifestDefinition,
    signcert,
    pkey,
    alg,
    tsaUrl
  );
}

export async function verifyJsoncAsset(
  asset: JsoncAssetInput,
  trustedCertificates: string[]
): Promise<wasm.VerificationOutcome> {
  assertValidJsoncAsset(asset);
  return verifyAsset(JSONC_FORMAT, encodeJsoncAsset(asset), trustedCertificates);
}

export async function signXmlAsset(
  asset: JsoncAssetInput,
  manifestDefinition: any,
  signcert: Uint8Array,
  pkey: Uint8Array,
  alg: wasm.SigningAlg,
  tsaUrl?: string
): Promise<wasm.C2PASignResult> {
  return signAsset(
    XML_FORMAT,
    ensureXmlManifestPlaceholder(asset),
    manifestDefinition,
    signcert,
    pkey,
    alg,
    tsaUrl
  );
}

export async function verifyXmlAsset(
  asset: JsoncAssetInput,
  trustedCertificates: string[]
): Promise<wasm.VerificationOutcome> {
  return verifyAsset(XML_FORMAT, encodeJsoncAsset(asset), trustedCertificates);
}

export async function signMarkdownAsset(
  asset: JsoncAssetInput,
  manifestDefinition: any,
  signcert: Uint8Array,
  pkey: Uint8Array,
  alg: wasm.SigningAlg,
  tsaUrl?: string
): Promise<wasm.C2PASignResult> {
  return signAsset(
    MD_FORMAT,
    ensureMarkdownManifestPlaceholder(asset),
    manifestDefinition,
    signcert,
    pkey,
    alg,
    tsaUrl
  );
}

export async function verifyMarkdownAsset(
  asset: JsoncAssetInput,
  trustedCertificates: string[]
): Promise<wasm.VerificationOutcome> {
  return verifyAsset(MD_FORMAT, encodeJsoncAsset(asset), trustedCertificates);
}

export { C2PASignResult } from '../pkg/c2pa_rs_wasm.js';
