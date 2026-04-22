import * as wasm from '../pkg';

export { SupportedFormat, VerificationOutcome, RecognizedManifest, C2PAThumbnail, C2PAIngredient } from '../pkg';

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
