import * as wasm from '../pkg/c2pa_rs_wasm.js';

export type { SupportedFormat, VerificationOutcome, RecognizedManifest, C2PAThumbnail, C2PAIngredient, SigningAlg } from '../pkg/c2pa_rs_wasm.js';

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

export { C2PASignResult } from '../pkg/c2pa_rs_wasm.js';
