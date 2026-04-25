# c2pa-rs-javascript-library

TypeScript/JavaScript bindings for [C2PA](https://c2pa.org/) (Coalition for Content Provenance and Authenticity) signing and verification, powered by Rust compiled to WebAssembly.

## What It Does

- **Sign** images, PDFs, SVGs, and text formats (JSONC, XML, Markdown) with C2PA manifests
- **Verify** C2PA manifests and extract provenance data
- **CAWG identity assertions** — prepare, sign, and verify named-actor identity credentials
- **Structured text** — first-class support for source code and document formats

Works in any bundler that supports WASM (Vite, webpack 5, Rollup, esbuild).

## Supported Formats

| MIME type | Format |
|---|---|
| `image/jpeg` | JPEG |
| `image/png` | PNG |
| `image/svg+xml` | SVG |
| `image/x-adobe-dng` | DNG |
| `application/pdf` | PDF |
| `jsonc` | JSONC / JSON with comments |
| `xml` | XML |
| `md` | Markdown |

## Installation

```bash
npm install c2pa-rs-javascript-library
```

## Quick Start

### Verify an asset

```ts
import { verifyAsset } from 'c2pa-rs-javascript-library';

const bytes = new Uint8Array(await file.arrayBuffer());

const result = await verifyAsset('image/jpeg', bytes, []);
console.log(result.state);       // true if trusted
console.log(result.manifests);   // array of recognized manifests
```

### Sign an asset

```ts
import { signAsset } from 'c2pa-rs-javascript-library';

const signcert = new Uint8Array(/* PEM bytes */);
const pkey     = new Uint8Array(/* private key bytes */);

const result = await signAsset(
  'image/jpeg',
  assetBytes,
  {
    claim_generator_info: [{ name: 'my-app' }],
    title: 'photo.jpg',
    assertions: [
      {
        label: 'c2pa.actions',
        data: { actions: [{ action: 'c2pa.created' }] },
      },
    ],
  },
  signcert,
  pkey,
  'es256'
);

// result.signedAsset — Uint8Array of the signed file
// result.manifest   — Uint8Array of the raw JUMBF manifest
```

### CAWG identity assertions

```ts
import {
  prepareIdentityAssertion,
  signIdentityAssertionPayloadX509,
  finalizeIdentityAssertion,
} from 'c2pa-rs-javascript-library';

// Step 1 — capture the signer payload
const prepared = await prepareIdentityAssertion(
  'image/png', assetBytes, manifest, signcert, pkey, 'es256',
  { sigType: 'cawg.x509.cose', reserveSize: 4096, roles: ['cawg.creator'] }
);

// Step 2 — sign with an external key / HSM
const signature = signIdentityAssertionPayloadX509(
  prepared.signerPayloadCbor, identitySigncert, identityPkey, 'es256'
);

// Step 3 — embed the real signature
const result = await finalizeIdentityAssertion(prepared, signature);
```

For a single-pass X.509 flow use `signAssetWithX509Identity(...)`.

### ICA (Identity Claims Aggregation) signing

```ts
import {
  computeIcaIssuerDid,
  signAssetWithIcaIdentity,
} from 'c2pa-rs-javascript-library';

// Derive the did:jwk DID for the issuer's Ed25519 key (32 raw bytes).
const issuerDid = computeIcaIssuerDid(issuerPrivateKeyBytes);

const result = await signAssetWithIcaIdentity(
  'image/png',
  assetBytes,
  manifest,
  signcert,
  pkey,
  'es256',
  issuerDid,
  issuerPrivateKeyBytes,  // 32-byte Ed25519 seed
  [
    {
      type: 'cawg.social_media',
      username: 'myhandle',
      uri: 'https://social.example.com/myhandle',
      verifiedAt: '2024-01-01T00:00:00Z',
      provider: { id: 'https://social.example.com', name: 'Example Social' },
    },
  ],
  { sigType: 'cawg.identity_claims_aggregation', reserveSize: 8192, roles: ['cawg.creator'] }
);
```

### Structured text (JSONC / XML / Markdown)

```ts
import { signJsoncAsset, verifyJsoncAsset } from 'c2pa-rs-javascript-library';

const signed = await signJsoncAsset(source, manifest, signcert, pkey, 'es256');
const result = await verifyJsoncAsset(signed.signedAsset, []);
```

Equivalent `signXmlAsset`, `verifyXmlAsset`, `signMarkdownAsset`, `verifyMarkdownAsset` helpers are also exported.

## API Reference

See [`src/index.ts`](src/index.ts) for full TypeScript signatures.

### Core

| Function | Description |
|---|---|
| `signAsset(format, asset, manifest, cert, key, alg, tsaUrl?)` | Sign any supported format |
| `verifyAsset(format, asset, trustedCerts)` | Verify and parse manifests |
| `cleanAsset(format, asset)` | Remove any embedded C2PA manifest |

### Identity assertions (CAWG)

| Function | Description |
|---|---|
| `prepareIdentityAssertion(...)` | Capture signer payload for external signing |
| `finalizeIdentityAssertion(prepared, signature)` | Embed externally produced signature |
| `signAssetWithX509Identity(...)` | Single-pass X.509 identity signing |
| `signIdentityAssertionPayloadX509(cbor, cert, key, alg)` | Sign a CBOR payload with X.509 |
| `verifyIdentityAssertions(format, asset, trustedCerts)` | Verify CAWG identity assertions |
| `computeIcaIssuerDid(privateKey)` | Derive `did:jwk` from a 32-byte Ed25519 seed |
| `signAssetWithIcaIdentity(...)` | Single-pass ICA (W3C VC) identity signing |

### CAWG metadata

| Function | Description |
|---|---|
| `addCawgMetadataAssertion(manifest, metadata)` | Add a `cawg.metadata` assertion |
| `signAssetWithCawgMetadata(...)` | Sign and attach CAWG metadata in one step |

### Structured text helpers

Each format has `sign*`, `verify*`, and `clean*` variants:

- `signJsoncAsset` / `verifyJsoncAsset` / `cleanJsoncAsset`
- `signXmlAsset` / `verifyXmlAsset` / `cleanXmlAsset`
- `signMarkdownAsset` / `verifyMarkdownAsset` / `cleanMarkdownAsset`

### Utilities

| Function | Description |
|---|---|
| `parseJsonc(asset)` | Parse JSONC (JSON with comments) to a plain object |

## Manifest definition

The `manifest` object passed to signing functions follows the C2PA `ManifestDefinition` schema:

```ts
{
  claim_generator_info: [{ name: string; version?: string }];
  title?: string;
  assertions?: { label: string; data: unknown }[];
  instance_id?: string;    // auto-generated if omitted
  label?: string;          // auto-generated if omitted
  assertion_salt?: number[]; // optional fixed salt for deterministic assertion hashes
}
```

## License

`MIT OR Apache-2.0`
