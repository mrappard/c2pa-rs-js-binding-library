# c2pa-rs-javascript-library

TypeScript/JavaScript bindings for [C2PA](https://c2pa.org/) (Coalition for Content Provenance and Authenticity) signing and verification, powered by Rust compiled to WebAssembly.

## What It Does

- **Sign** images, PDFs, SVGs, and text formats (JSONC, XML, Markdown) with C2PA manifests
- **Verify** C2PA manifests and extract provenance data
- **Sidecar manifests** — produce a separate `.c2pa` file for assets that cannot be modified (AI/ML datasets)
- **CAWG identity assertions** — prepare, sign, and verify named-actor identity credentials (X.509 and ICA/W3C VC)
- **Structured text** — first-class support for source code and document formats

Works in any bundler that supports WASM (Vite, webpack 5, Rollup, esbuild).

## Supported Formats

| MIME type / format string | Format |
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

`signAsset` accepts an options object. The required fields are `format`, `asset`, `manifestDefinition`, `signcert`, `pkey`, and `alg`. Everything else is optional.

```ts
import { signAsset } from 'c2pa-rs-javascript-library';

const signcert = new Uint8Array(/* PEM bytes */);
const pkey     = new Uint8Array(/* private key bytes */);

const result = await signAsset({
  format: 'image/jpeg',
  asset: assetBytes,           // Uint8Array or string (string accepted for text formats)
  manifestDefinition: {
    claim_generator_info: [{ name: 'my-app' }],
    title: 'photo.jpg',
    assertions: [
      { label: 'c2pa.actions', data: { actions: [{ action: 'c2pa.created' }] } },
    ],
  },
  signcert,
  pkey,
  alg: 'es256',
  tsaUrl: 'http://timestamp.digicert.com', // optional
});

// result.signedAsset — Uint8Array of the signed file
// result.manifest   — Uint8Array of the raw JUMBF manifest
```

### Signing with a thumbnail

Pass `thumbnailFormat` and `thumbnailData` together:

```ts
const result = await signAsset({
  format: 'image/jpeg',
  asset: assetBytes,
  manifestDefinition: manifest,
  signcert, pkey, alg: 'es256',
  thumbnailFormat: 'image/jpeg',
  thumbnailData: thumbnailBytes,
});
```

### Signing with a parent ingredient

Pass `parentFormat`, `parentAsset`, and `parentTitle` together:

```ts
const result = await signAsset({
  format: 'image/jpeg',
  asset: derivedBytes,
  manifestDefinition: manifest,
  signcert, pkey, alg: 'es256',
  parentFormat: 'image/jpeg',
  parentAsset: sourceBytes,   // must already be signed
  parentTitle: 'source.jpg',
});
```

### Signing with multiple ingredients

Use `signAssetWithIngredients` for more than one ingredient:

```ts
import { signAssetWithIngredients } from 'c2pa-rs-javascript-library';

const result = await signAssetWithIngredients(
  'md',
  bodyBytes,
  manifest,
  signcert, pkey, 'es256',
  [
    { format: 'md', asset: docA.signedAsset, title: 'doc-a.md', relationship: 'parentOf' },
    { format: 'md', asset: docB.signedAsset, title: 'doc-b.md', relationship: 'componentOf' },
  ]
);
```

### Structured text (JSONC / XML / Markdown)

Pass the format string and the asset as a plain string (or `Uint8Array`). The placeholder comment required by C2PA is injected automatically:

```ts
import { signAsset, verifyMarkdownAsset } from 'c2pa-rs-javascript-library';

const result = await signAsset({
  format: 'md',
  asset: '# My document\n\nSome content.',  // string accepted directly
  manifestDefinition: manifest,
  signcert, pkey, alg: 'es256',
});

const outcome = await verifyMarkdownAsset(result.signedAsset, [certPem]);
```

Equivalent verify and clean helpers exist for each text format:

| Format | Verify | Clean |
|---|---|---|
| JSONC | `verifyJsoncAsset(asset, certs)` | `cleanJsoncAsset(asset)` |
| XML | `verifyXmlAsset(asset, certs)` | `cleanXmlAsset(asset)` |
| Markdown | `verifyMarkdownAsset(asset, certs)` | `cleanMarkdownAsset(asset)` |

### Sidecar manifests (AI/ML datasets)

A sidecar produces a separate `.c2pa` manifest file — the original asset is never modified. This follows the [C2PA AI/ML specification](https://spec.c2pa.org/specifications/specifications/1.3/ai-ml/ai_ml.html).

```ts
import { signAssetSidecar, verifyAssetFromSidecar } from 'c2pa-rs-javascript-library';

// Sign — returns the original (unmodified) asset and a sidecar manifest
const result = await signAssetSidecar({
  format: 'image/jpeg',
  asset: datasetBytes,
  manifestDefinition: manifest,
  signcert, pkey, alg: 'es256',
});

// result.signedAsset — original bytes, unchanged
// result.manifest   — JUMBF sidecar bytes (.c2pa file)

// Verify — pass both the asset and its sidecar
const outcome = await verifyAssetFromSidecar({
  format: 'image/jpeg',
  asset: datasetBytes,
  sidecar: result.manifest,
  trustedCertificates: [certPem],
});
```

`signAssetSidecar` accepts the same optional fields as `signAsset` (`thumbnailFormat`/`thumbnailData`, `parentFormat`/`parentAsset`/`parentTitle`, and all identity fields).

### CAWG X.509 identity assertions

Single-pass signing embeds an identity assertion directly:

```ts
import { signAsset } from 'c2pa-rs-javascript-library';

const result = await signAsset({
  format: 'image/png',
  asset: assetBytes,
  manifestDefinition: manifest,
  signcert, pkey, alg: 'es256',
  // identity fields
  identitySigncert: idSigncert,
  identityPkey: idPkey,
  identityAlg: 'es256',
  identityOptions: {
    sigType: 'cawg.x509.cose',
    reserveSize: 4096,
    referencedAssertions: ['c2pa.actions'],
    roles: ['cawg.creator'],
  },
});
```

For an external-signer / HSM flow use the two-step API:

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

### ICA (Identity Claims Aggregation) signing

```ts
import { computeIcaIssuerDid, signAsset } from 'c2pa-rs-javascript-library';

// Derive the did:jwk DID for the issuer's Ed25519 key (32 raw bytes).
const issuerDid = computeIcaIssuerDid(issuerPrivateKeyBytes);

const result = await signAsset({
  format: 'image/png',
  asset: assetBytes,
  manifestDefinition: manifest,
  signcert, pkey, alg: 'es256',
  // ICA identity fields
  issuerDid,
  issuerPrivateKey: issuerPrivateKeyBytes,  // 32-byte Ed25519 seed
  verifiedIdentities: [
    {
      type: 'cawg.social_media',
      username: 'myhandle',
      uri: 'https://social.example.com/myhandle',
      verifiedAt: '2024-01-01T00:00:00Z',
      provider: { id: 'https://social.example.com', name: 'Example Social' },
    },
  ],
  icaOptions: {
    sigType: 'cawg.identity_claims_aggregation',
    reserveSize: 8192,
    roles: ['cawg.creator'],
  },
});
```

## API Reference

See [`src/index.ts`](src/index.ts) for full TypeScript signatures.

### Core

| Function | Description |
|---|---|
| `signAsset(options)` | Sign any supported format (see `SignAssetOptions`) |
| `verifyAsset(format, asset, trustedCerts)` | Verify and parse manifests |
| `cleanAsset(format, asset)` | Remove any embedded C2PA manifest |
| `getResource(format, asset, uri)` | Retrieve a named resource from a signed asset |
| `signAssetWithIngredients(format, asset, manifest, cert, key, alg, ingredients, tsaUrl?)` | Sign with multiple ingredients |

### Sidecar manifests

| Function | Description |
|---|---|
| `signAssetSidecar(options)` | Sign without modifying the asset; returns sidecar bytes (see `SignAssetSidecarOptions`) |
| `verifyAssetFromSidecar(options)` | Verify an asset using a separate sidecar manifest |

### Identity assertions (CAWG)

| Function | Description |
|---|---|
| `prepareIdentityAssertion(...)` | Capture signer payload for external signing |
| `finalizeIdentityAssertion(prepared, signature)` | Embed externally produced signature |
| `signIdentityAssertionPayloadX509(cbor, cert, key, alg)` | Sign a CBOR payload with X.509 |
| `verifyIdentityAssertions(format, asset, trustedCerts)` | Verify CAWG identity assertions |
| `computeIcaIssuerDid(privateKey)` | Derive `did:jwk` from a 32-byte Ed25519 seed |

### CAWG metadata

| Function | Description |
|---|---|
| `addCawgMetadataAssertion(manifest, metadata)` | Add a `cawg.metadata` assertion to a manifest definition |
| `signAssetWithCawgMetadata(...)` | Sign and attach CAWG metadata in one step |

### Structured text helpers

| Format | Verify | Clean | Parse |
|---|---|---|---|
| JSONC | `verifyJsoncAsset` | `cleanJsoncAsset` | `parseJsonc` |
| XML | `verifyXmlAsset` | `cleanXmlAsset` | — |
| Markdown | `verifyMarkdownAsset` | `cleanMarkdownAsset` | — |

Signing text formats is done via `signAsset` with `format: 'jsonc' | 'xml' | 'md'` and `asset: string | Uint8Array`.

## `SignAssetOptions`

```ts
type SignAssetOptions = {
  // Required
  format: SupportedFormat;
  asset: Uint8Array | string;   // string accepted for jsonc, xml, md
  manifestDefinition: object;
  signcert: Uint8Array;
  pkey: Uint8Array;
  alg: SigningAlg;

  // Optional
  tsaUrl?: string;

  // Thumbnail
  thumbnailFormat?: string;
  thumbnailData?: Uint8Array;

  // Parent ingredient (single)
  parentFormat?: SupportedFormat;
  parentAsset?: Uint8Array;
  parentTitle?: string;

  // X.509 identity assertion
  identitySigncert?: Uint8Array;
  identityPkey?: Uint8Array;
  identityAlg?: SigningAlg;
  identityOptions?: IdentityAssertionOptions;
  identityTsaUrl?: string;

  // ICA identity assertion
  issuerDid?: string;
  issuerPrivateKey?: Uint8Array;
  verifiedIdentities?: IcaVerifiedIdentity[];
  icaOptions?: IdentityAssertionOptions;
};
```

`SignAssetSidecarOptions` has the same shape.

## Manifest definition

```ts
{
  claim_generator_info: [{ name: string; version?: string }];
  title?: string;
  assertions?: { label: string; data: unknown }[];
  instance_id?: string;      // auto-generated if omitted
  label?: string;            // auto-generated if omitted
  assertion_salt?: number[]; // optional fixed salt for deterministic assertion hashes
}
```

## Signing algorithms

`SigningAlg`: `'es256'` | `'es384'` | `'es512'` | `'ps256'` | `'ps384'` | `'ps512'` | `'ed25519'`

## License

`MIT OR Apache-2.0`
