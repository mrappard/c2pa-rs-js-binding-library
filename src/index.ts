import * as wasm from '../pkg/c2pa_rs_wasm.js';
import { parse, printParseErrorCode, type ParseError } from 'jsonc-parser';

export type { SupportedFormat, VerificationOutcome, RecognizedManifest, C2PAThumbnail, C2PAIngredient, SigningAlg } from '../pkg/c2pa_rs_wasm.js';

const JSONC_FORMAT = 'jsonc' as wasm.SupportedFormat;
const CAWG_METADATA_LABEL = 'cawg.metadata';
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
export type CawgMetadataContext = Record<string, string>;
export type CawgMetadataAssertion = {
  '@context': CawgMetadataContext;
  [key: string]: unknown;
};
export type IdentityAssertionOptions = {
  sigType: string;
  reserveSize: number;
  referencedAssertions?: string[];
  roles?: string[];
};
export type PreparedIdentityAssertion = {
  format: wasm.SupportedFormat;
  asset: Uint8Array;
  manifestDefinition: unknown;
  signcert: Uint8Array;
  pkey: Uint8Array;
  alg: wasm.SigningAlg;
  tsaUrl?: string;
  options: IdentityAssertionOptions;
  signerPayload: Record<string, unknown>;
  signerPayloadCbor: Uint8Array;
};
export type IdentityAssertionRecord = {
  label: string;
  validated: boolean;
  data: Record<string, unknown>;
};
export type IdentityAssertionVerificationOutcome = {
  manifests: Record<string, IdentityAssertionRecord[]>;
};

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function assertValidCawgMetadata(metadata: unknown): asserts metadata is CawgMetadataAssertion {
  if (!isPlainObject(metadata)) {
    throw new Error('Invalid CAWG metadata: expected a JSON object');
  }

  const context = metadata['@context'];
  if (!isPlainObject(context)) {
    throw new Error('Invalid CAWG metadata: "@context" must be an object');
  }

  const contextEntries = Object.entries(context);
  if (contextEntries.length === 0) {
    throw new Error('Invalid CAWG metadata: "@context" must not be empty');
  }

  for (const [, uri] of contextEntries) {
    if (typeof uri !== 'string' || uri.length === 0) {
      throw new Error('Invalid CAWG metadata: all "@context" values must be non-empty strings');
    }
  }

  if (Object.keys(metadata).every((key) => key === '@context')) {
    throw new Error('Invalid CAWG metadata: include at least one metadata field besides "@context"');
  }
}

function decodeJsoncAsset(asset: JsoncAssetInput): string {
  return typeof asset === 'string' ? asset : textDecoder.decode(asset);
}

function encodeJsoncAsset(asset: JsoncAssetInput): Uint8Array {
  return typeof asset === 'string' ? textEncoder.encode(asset) : asset;
}

function assertValidJsoncAsset(asset: JsoncAssetInput): string {
  const text = decodeJsoncAsset(asset);
  const errors: ParseError[] = [];

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

export async function verifyIdentityAssertions(
  format: wasm.SupportedFormat,
  asset: Uint8Array,
  trustedCertificates: string[]
): Promise<IdentityAssertionVerificationOutcome> {
  return wasm.verify_identity_assertions(format, asset, trustedCertificates) as Promise<IdentityAssertionVerificationOutcome>;
}

export function cleanAsset(
  format: wasm.SupportedFormat,
  asset: Uint8Array
): Uint8Array {
  return wasm.clean_asset(format, asset);
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

export async function prepareIdentityAssertion(
  format: wasm.SupportedFormat,
  asset: Uint8Array,
  manifestDefinition: Record<string, unknown>,
  signcert: Uint8Array,
  pkey: Uint8Array,
  alg: wasm.SigningAlg,
  options: IdentityAssertionOptions,
  tsaUrl?: string
): Promise<PreparedIdentityAssertion> {
  return wasm.prepare_identity_assertion(
    format,
    asset,
    manifestDefinition,
    signcert,
    pkey,
    alg,
    tsaUrl,
    {
      sigType: options.sigType,
      reserveSize: options.reserveSize,
      referencedAssertions: options.referencedAssertions ?? [],
      roles: options.roles ?? [],
    }
  ) as Promise<PreparedIdentityAssertion>;
}

export async function finalizeIdentityAssertion(
  prepared: PreparedIdentityAssertion,
  signature: Uint8Array
): Promise<wasm.C2PASignResult> {
  return wasm.finalize_identity_assertion(prepared, signature);
}

export function signIdentityAssertionPayloadX509(
  signerPayloadCbor: Uint8Array,
  signcert: Uint8Array,
  pkey: Uint8Array,
  alg: wasm.SigningAlg,
  tsaUrl?: string
): Uint8Array {
  return wasm.sign_identity_assertion_payload_x509(signerPayloadCbor, signcert, pkey, alg, tsaUrl);
}

export async function signAssetWithX509Identity(
  format: wasm.SupportedFormat,
  asset: Uint8Array,
  manifestDefinition: Record<string, unknown>,
  signcert: Uint8Array,
  pkey: Uint8Array,
  alg: wasm.SigningAlg,
  identitySigncert: Uint8Array,
  identityPkey: Uint8Array,
  identityAlg: wasm.SigningAlg,
  options: IdentityAssertionOptions,
  tsaUrl?: string,
  identityTsaUrl?: string
): Promise<wasm.C2PASignResult> {
  return wasm.sign_asset_with_x509_identity(
    format,
    asset,
    manifestDefinition,
    signcert,
    pkey,
    alg,
    identitySigncert,
    identityPkey,
    identityAlg,
    {
      sigType: options.sigType,
      reserveSize: options.reserveSize,
      referencedAssertions: options.referencedAssertions ?? [],
      roles: options.roles ?? [],
    },
    tsaUrl,
    identityTsaUrl
  );
}

export function addCawgMetadataAssertion(
  manifestDefinition: Record<string, unknown>,
  metadata: CawgMetadataAssertion
): Record<string, unknown> {
  assertValidCawgMetadata(metadata);

  const assertions = Array.isArray(manifestDefinition.assertions)
    ? [...manifestDefinition.assertions]
    : [];

  assertions.push({
    label: CAWG_METADATA_LABEL,
    data: metadata,
  });

  return {
    ...manifestDefinition,
    assertions,
  };
}

export async function signAssetWithCawgMetadata(
  format: wasm.SupportedFormat,
  asset: Uint8Array,
  manifestDefinition: Record<string, unknown>,
  metadata: CawgMetadataAssertion,
  signcert: Uint8Array,
  pkey: Uint8Array,
  alg: wasm.SigningAlg,
  tsaUrl?: string
): Promise<wasm.C2PASignResult> {
  return signAsset(
    format,
    asset,
    addCawgMetadataAssertion(manifestDefinition, metadata),
    signcert,
    pkey,
    alg,
    tsaUrl
  );
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

export function cleanJsoncAsset(asset: JsoncAssetInput): Uint8Array {
  return cleanAsset(JSONC_FORMAT, encodeJsoncAsset(asset));
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

export function cleanXmlAsset(asset: JsoncAssetInput): Uint8Array {
  return cleanAsset(XML_FORMAT, encodeJsoncAsset(asset));
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

export function cleanMarkdownAsset(asset: JsoncAssetInput): Uint8Array {
  return cleanAsset(MD_FORMAT, encodeJsoncAsset(asset));
}

export { C2PASignResult } from '../pkg/c2pa_rs_wasm.js';
