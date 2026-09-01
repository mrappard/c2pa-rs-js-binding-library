// Reference implementation for the "org.c2pa/credential" MCP _meta proposal.
//
// Run with:
//   npm run test:wasm   (once, to build pkg/ for Node — see CLAUDE.md)
//   node --input-type=module -e "import('./demo/mcp-c2pa-credentials.ts')"
//
// What's real cryptography here vs. illustrative:
//
//   - The ImageContent credential is a genuine C2PA manifest, produced and
//     validated by the actual c2pa-rs WASM module in this repo via
//     signAssetSidecar() / verifyAssetFromSidecar() — the exact primitive
//     the MCP convention needs: sign a detached manifest, don't touch the
//     asset. Nothing about the signature-chain + hard-binding validation is
//     simplified.
//
//     This used to be broken in this repo: signAssetSidecar's WASM binding
//     (crate/src/lib.rs) signed the manifest over whatever Builder::sign()
//     actually wrote to its `dest` stream, then discarded those bytes and
//     returned the pristine, untouched input as `signedAsset` instead. For
//     PNG/JPEG, c2pa-rs's manifest-removal pass (run even when there's
//     nothing to remove) doesn't byte-for-byte round-trip, so the hash the
//     manifest was signed over never matched the asset bytes this wrapper
//     handed back — verify_asset_from_sidecar's ValidationState was never
//     Trusted, tampered or not (test/sidecar.test.js had no test asserting
//     state===true for this path, and its tamper test only checked "false
//     or throws" — the fingerprint of a check that could never pass either
//     way). Fixed by returning `dest.into_inner()` instead of `asset` in
//     sign_asset_sidecar and its ingredient/thumbnail/parent-ingredient/
//     x509-identity/ICA-identity siblings; test/sidecar.test.js now asserts
//     state===true on the untampered baseline for the plain and thumbnail/
//     ingredient/asset-reference/SVG cases. Note this means `signedAsset`
//     is not always byte-identical to the input even now — it's the bytes
//     actually hashed, which is what must be validated.
//
//     Still open, and NOT covered by the above fix: sidecar signing with a
//     CAWG identity assertion (X509 or ICA) does not reach Trusted state
//     either, before or after this fix — every existing test for those
//     paths (embedded or sidecar) avoids asserting state for exactly this
//     reason. Looks like a second, unrelated gap, likely CAWG identity
//     validation needing its own trust-anchor wiring distinct from
//     `trust.trust_anchors`. Out of scope here.
//
//   - The TextContent credential and the Level-2 composite credential
//     implement a hashing/signing rule that does NOT exist in c2pa-rs yet
//     (NFC-normalized-text hashing, and JCS-over-the-result-with-_meta-
//     stripped hashing). c2pa-rs has no "sign these exact bytes with no
//     format-specific handling" entry point, so this demo signs and
//     verifies them by hand with real ECDSA P-256 / SHA-256 (node:crypto),
//     using the same sample key/cert this repo's tests use. The resulting
//     credential is a small JSON object, clearly NOT a JUMBF/COSE_Sign1
//     byte stream — a production implementation of these two rules belongs
//     in c2pa-rs itself (see the CLAUDE.md-adjacent proposal writeup this
//     demo accompanies).
//
// The point of the demo is to show the two-level model catching two
// different classes of tampering: per-asset byte tampering (caught by the
// per-block credential) and structural tampering — reordering, insertion,
// swapping which credential goes with which block — that per-asset checks
// alone are blind to but the Level-2 composite binding catches.

import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash, createPrivateKey, sign as cryptoSign, verify as cryptoVerify, X509Certificate } from 'node:crypto';
import { signAssetSidecar, verifyAssetFromSidecar } from '../src/index.ts';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SAMPLE_DIR = join(__dirname, '..', 'test', 'assets', 'sample');
const PNG_PATH = join(__dirname, '..', 'test', 'assets', 'image', 'good', 'png', 'ChatGPT_Image.png');

const ORG_C2PA_CREDENTIAL = 'org.c2pa/credential';

// ---------------------------------------------------------------------------
// MCP shapes (trimmed to what this demo needs — see the MCP schema for the
// full ContentBlock / CallToolResult definitions).
// ---------------------------------------------------------------------------

type Meta = Record<string, unknown>;

interface TextContent {
  type: 'text';
  text: string;
  _meta?: Meta;
}

interface ImageContent {
  type: 'image';
  data: string; // base64
  mimeType: string;
  _meta?: Meta;
}

type ContentBlock = TextContent | ImageContent;

interface CallToolResult {
  content: ContentBlock[];
  structuredContent?: Record<string, unknown>;
  isError?: boolean;
  _meta?: Meta;
}

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------

function sha256(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(createHash('sha256').update(bytes).digest());
}

function b64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

function fromB64(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, 'base64'));
}

function dataUri(mediaType: string, bytes: Uint8Array): string {
  return `data:${mediaType};base64,${b64(bytes)}`;
}

function decodeDataUri(uri: string): Uint8Array {
  const marker = ';base64,';
  const idx = uri.indexOf(marker);
  if (idx === -1) throw new Error(`not a base64 data URI: ${uri.slice(0, 40)}...`);
  return fromB64(uri.slice(idx + marker.length));
}

// NFC-normalized, UTF-8-encoded bytes of a string value — the hard-binding
// input the proposal specifies for TextContent / TextResourceContents,
// mirroring the NFC rule C2PA already mandates for unstructured-text
// bindings. No exclusion ranges apply here because nothing is embedded
// in-band; the credential travels out-of-band in _meta.
function textAssetBytes(text: string): Uint8Array {
  return new TextEncoder().encode(text.normalize('NFC'));
}

// Recursively strip every `_meta` member from a JSON value — not just the
// top-level one on the Result. This is deliberate: content blocks nested
// inside `content` carry their own per-asset `_meta["org.c2pa/credential"]`,
// and those values (URIs) are exactly the kind of thing a conforming
// intermediary might rewrite in flight. If the composite hash captured them,
// re-hosting an ingredient's manifest at a new URL — with the ingredient's
// own hash-of-bytes completely unchanged — would silently break the
// composite binding.
function stripMetaDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stripMetaDeep);
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (k === '_meta') continue;
      out[k] = stripMetaDeep(v);
    }
    return out;
  }
  return value;
}

// Minimal RFC 8785 (JCS) canonicalizer. Handles what this demo's data shapes
// need: object key sorting (JS's default string sort is UTF-16-code-unit
// order, which is what JCS requires) and JS's native Number::toString,
// which for finite numbers *is* the ECMAScript algorithm JCS mandates —
// so this is spec-correct for numbers that survive JSON.parse. It is NOT a
// complete, hardened JCS implementation (string escaping doesn't handle
// every edge case RFC 8785 §3.2.2.2 does); use a real library
// (e.g. `canonicalize` on npm) in production.
function jcs(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('JCS: non-finite number is not representable');
    return String(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(jcs).join(',') + ']';
  if (typeof value === 'object') {
    const keys = Object.keys(value as object).sort();
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + jcs((value as Record<string, unknown>)[k])).join(',') + '}';
  }
  throw new Error(`JCS: unsupported value type ${typeof value}`);
}

function signWithSampleKey(data: Uint8Array, pkeyPem: Buffer): Uint8Array {
  const key = createPrivateKey(pkeyPem);
  return new Uint8Array(cryptoSign('sha256', data, key));
}

function verifyWithCert(data: Uint8Array, signature: Uint8Array, certPem: string): boolean {
  const cert = new X509Certificate(certPem);
  return cryptoVerify('sha256', data, cert.publicKey, signature);
}

// ---------------------------------------------------------------------------
// The "toy" JSON credential shape used for the two rules c2pa-rs doesn't
// implement yet (text hard-binding, composite JCS hard-binding). Explicitly
// NOT claiming to be a JUMBF/COSE_Sign1 byte stream.
// ---------------------------------------------------------------------------

interface DemoCredential {
  demoNote: string;
  hashAlg: 'sha256';
  hashData: string; // base64
  sigAlg: 'ecdsa-p256-sha256';
  signature: string; // base64
  certChain: string; // PEM
  ingredients?: { block: number; type: string; assetHash: string }[];
}

function makeDemoCredential(
  hash: Uint8Array,
  pkeyPem: Buffer,
  certPem: string,
  note: string,
  ingredients?: DemoCredential['ingredients'],
): Uint8Array {
  const credential: DemoCredential = {
    demoNote: note,
    hashAlg: 'sha256',
    hashData: b64(hash),
    sigAlg: 'ecdsa-p256-sha256',
    signature: b64(signWithSampleKey(hash, pkeyPem)),
    certChain: certPem,
    ...(ingredients ? { ingredients } : {}),
  };
  return new TextEncoder().encode(JSON.stringify(credential));
}

function verifyDemoCredential(bytes: Uint8Array): { credential: DemoCredential; sigOk: boolean } {
  const credential: DemoCredential = JSON.parse(new TextDecoder().decode(bytes));
  const sigOk = verifyWithCert(fromB64(credential.hashData), fromB64(credential.signature), credential.certChain);
  return { credential, sigOk };
}

// ---------------------------------------------------------------------------
// Main demo
// ---------------------------------------------------------------------------

async function main() {
  const signcert = new Uint8Array(readFileSync(join(SAMPLE_DIR, 'es256_certs.pem')));
  const pkey = new Uint8Array(readFileSync(join(SAMPLE_DIR, 'es256_private.key')));
  const pkeyPem = readFileSync(join(SAMPLE_DIR, 'es256_private.key'));
  const certPem = readFileSync(join(SAMPLE_DIR, 'es256_certs.pem'), 'utf-8');

  console.log('=== Building an MCP CallToolResult with org.c2pa/credential attached ===\n');

  // --- Level 1, block 0: a real, signed image -----------------------------
  // signAssetSidecar produces a *detached* manifest without embedding
  // anything into the asset — the primitive the MCP convention actually
  // wants: the tool's image payload carries its own hard binding out of
  // band via _meta, no format-specific re-encoding required. See the
  // file-header note on the bug this used to hit.
  const pngBytes = new Uint8Array(readFileSync(PNG_PATH));
  const signed = await signAssetSidecar({
    format: 'image/png',
    asset: pngBytes,
    manifestDefinition: {
      claim_generator_info: [{ name: 'mcp-c2pa-demo' }],
      title: 'tool-result-image.png',
      assertions: [
        {
          label: 'c2pa.actions',
          data: { actions: [{ action: 'c2pa.created', digitalSourceType: 'http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia' }] },
        },
      ],
    },
    signcert,
    pkey,
    alg: 'es256',
  });
  const imageSidecar = signed.manifest;
  console.log(`image manifest: ${imageSidecar.length} bytes (real JUMBF/COSE, produced by c2pa-rs)`);
  console.log(`image asset bytes: ${signed.signedAsset.length} (input was ${pngBytes.length} — see file-header note: not always byte-identical)`);

  const imageBlock: ImageContent = {
    type: 'image',
    data: b64(signed.signedAsset),
    mimeType: 'image/png',
    _meta: { [ORG_C2PA_CREDENTIAL]: dataUri('application/c2pa', imageSidecar) },
  };

  // --- Level 1, block 1: generated text ------------------------------------
  const summaryText = 'The uploaded photo shows a golden retriever sitting in a park at sunset.';
  const textHash = textAssetBytes(summaryText);
  const textCredentialBytes = makeDemoCredential(
    sha256(textHash),
    pkeyPem,
    certPem,
    'DEMO ONLY — illustrates the proposed c2pa.hash.data(NFC-text, no-exclusions) rule for MCP TextContent. Not a JUMBF/COSE byte stream.',
  );
  const textBlock: TextContent = {
    type: 'text',
    text: summaryText,
    _meta: { [ORG_C2PA_CREDENTIAL]: dataUri('application/vnd.c2pa-mcp-demo+json', textCredentialBytes) },
  };

  // --- Assemble the result, with a deliberately-precision-losing integer
  //     in structuredContent to make the JCS-number caveat concrete below.
  const result: CallToolResult = {
    content: [imageBlock, textBlock],
    structuredContent: { requestId: 9007199254740993, confidence: 0.94 },
  };

  // --- Level 2: composite binding over JCS(result with all _meta stripped)
  const stripped = stripMetaDeep(result);
  const canonical = jcs(stripped);
  const compositeHash = sha256(new TextEncoder().encode(canonical));
  const compositeCredentialBytes = makeDemoCredential(
    compositeHash,
    pkeyPem,
    certPem,
    'DEMO ONLY — Level-2 composite binding: SHA-256 over JCS(Result) with every _meta member removed. Ingredients bind by hash of each block\'s own asset bytes.',
    [
      { block: 0, type: 'image', assetHash: b64(sha256(signed.signedAsset)) },
      { block: 1, type: 'text', assetHash: b64(sha256(textHash)) },
    ],
  );
  result._meta = { [ORG_C2PA_CREDENTIAL]: dataUri('application/vnd.c2pa-mcp-demo+json', compositeCredentialBytes) };

  console.log(`composite canonical JSON: ${canonical.length} bytes`);
  console.log(`composite hash: ${Buffer.from(compositeHash).toString('hex')}\n`);

  // ---------------------------------------------------------------------
  // Validation
  // ---------------------------------------------------------------------

  async function validateImageBlock(block: ImageContent): Promise<{ ok: boolean; assetHash: Uint8Array }> {
    const credUri = block._meta?.[ORG_C2PA_CREDENTIAL] as string;
    const sidecar = decodeDataUri(credUri);
    const assetBytes = fromB64(block.data);
    const outcome = await verifyAssetFromSidecar({
      format: block.mimeType as 'image/png',
      asset: assetBytes,
      sidecar,
      // A real validator supplies its own trust anchors, not the signer's own
      // cert — using certPem here only because this demo's "client" and
      // "server" happen to share the same sample cert. state=true requires
      // both a matching hard binding AND a chain to a trusted anchor.
      trustedCertificates: [certPem],
    });
    return { ok: outcome.state === true, assetHash: sha256(assetBytes) };
  }

  function validateTextBlock(block: TextContent): { ok: boolean; assetHash: Uint8Array } {
    const credUri = block._meta?.[ORG_C2PA_CREDENTIAL] as string;
    const { credential, sigOk } = verifyDemoCredential(decodeDataUri(credUri));
    const recomputed = sha256(textAssetBytes(block.text));
    const hashOk = Buffer.compare(fromB64(credential.hashData), recomputed) === 0;
    return { ok: sigOk && hashOk, assetHash: recomputed };
  }

  function validateComposite(r: CallToolResult, perBlockHashes: Uint8Array[]): { ok: boolean; hashOk: boolean; sigOk: boolean; ingredientsOk: boolean } {
    const credUri = r._meta?.[ORG_C2PA_CREDENTIAL] as string;
    const { credential, sigOk } = verifyDemoCredential(decodeDataUri(credUri));
    const strippedNow = stripMetaDeep(r);
    const canonicalNow = jcs(strippedNow);
    const recomputed = sha256(new TextEncoder().encode(canonicalNow));
    const hashOk = Buffer.compare(fromB64(credential.hashData), recomputed) === 0;
    const ingredientsOk = (credential.ingredients ?? []).every(
      (ing) => perBlockHashes[ing.block] && Buffer.compare(fromB64(ing.assetHash), perBlockHashes[ing.block]) === 0,
    );
    return { ok: hashOk && sigOk && ingredientsOk, hashOk, sigOk, ingredientsOk };
  }

  async function runValidation(label: string, r: CallToolResult) {
    console.log(`--- ${label} ---`);
    // Locate blocks by type rather than array position: tamper test 3
    // deliberately reorders `content`, and per-asset validation should be
    // indifferent to where a block sits in the array.
    const imageBlock = r.content.find((b): b is ImageContent => b.type === 'image')!;
    const textBlockNow = r.content.find((b): b is TextContent => b.type === 'text')!;
    const imgResult = await validateImageBlock(imageBlock);
    const txtResult = validateTextBlock(textBlockNow);
    console.log(`  image block per-asset:      ${imgResult.ok ? 'PASS' : 'FAIL'}`);
    console.log(`  text block  per-asset:      ${txtResult.ok ? 'PASS' : 'FAIL'}`);
    // Ingredient hashes are indexed by logical role (0=image, 1=text) as
    // recorded at signing time, independent of current array order.
    const composite = validateComposite(r, [imgResult.assetHash, txtResult.assetHash]);
    console.log(`  composite:                  ${composite.ok ? 'PASS' : 'FAIL'} (hash=${composite.hashOk}, sig=${composite.sigOk}, ingredients=${composite.ingredientsOk})`);
    console.log();
  }

  await runValidation('Baseline: untampered result', result);

  // --- Tamper test 1: flip a byte in the image payload ---------------------
  // Per-asset validation must fail — the hard binding no longer matches the
  // asset bytes. Nothing is embedded in this asset (sidecar mode), so the
  // hard binding has no exclusion zones — any flipped byte should do it.
  const tamperedImageAsset = structuredClone(result);
  const tamperedBytes = fromB64((tamperedImageAsset.content[0] as ImageContent).data);
  tamperedBytes[tamperedBytes.length - 100] ^= 0xff;
  (tamperedImageAsset.content[0] as ImageContent).data = b64(tamperedBytes);
  await runValidation('Tamper test 1: image bytes altered after signing', tamperedImageAsset);

  // --- Tamper test 2: edit the text content ---------------------------------
  const tamperedText = structuredClone(result);
  (tamperedText.content[1] as TextContent).text = summaryText.replace('golden retriever', 'wolf');
  await runValidation('Tamper test 2: text content edited after signing', tamperedText);

  // --- Tamper test 3: reorder content blocks (no bytes touched) ------------
  // Both per-asset credentials still validate individually — the bytes
  // behind each block are untouched. Only the composite catches this,
  // because the JCS hash covers array order.
  const reordered = structuredClone(result);
  reordered.content = [reordered.content[1], reordered.content[0]];
  await runValidation('Tamper test 3: content blocks reordered (bytes untouched)', reordered);

  // ---------------------------------------------------------------------
  // Appendix: the JCS-number caveat, demonstrated directly.
  // ---------------------------------------------------------------------
  console.log('=== Appendix: JCS number round-trip caveat ===');
  const wireJson = '{"requestId":9007199254740993}';
  const parsed = JSON.parse(wireJson);
  console.log(`  original wire literal: 9007199254740993`);
  console.log(`  after JSON.parse -> Number -> String: ${String(parsed.requestId)}`);
  console.log(`  round-trips cleanly: ${String(parsed.requestId) === '9007199254740993'}`);
  console.log('  -> a composite binding computed after JSON.parse cannot see the original');
  console.log('     digits; a server and a client parsing the same wire bytes will compute');
  console.log('     the same (wrong-relative-to-source) hash, so signature verification');
  console.log('     still succeeds — the risk is silent data loss in structuredContent, not');
  console.log('     a validation bypass. Still worth flagging in the spec text.');
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
