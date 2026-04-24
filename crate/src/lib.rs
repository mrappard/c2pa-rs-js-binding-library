use std::{collections::HashMap, io::Cursor};
use wasm_bindgen::prelude::*;
use c2pa::{Context, Reader, ValidationState, settings::Settings};
use serde::{Deserialize, Serialize};
use strum::{EnumString, IntoStaticStr};
use tsify::Tsify;

const CREDENTIALS_ASSERTION_LABEL: &str = "io.vaultie.credentials";

#[wasm_bindgen]
pub fn hello_world() -> String {
    "Hello from Rust with C2PA!".into()
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, EnumString, IntoStaticStr, Tsify)]
#[tsify(from_wasm_abi)]
pub enum SupportedFormat {
    #[serde(rename = "application/pdf")]
    #[strum(serialize = "application/pdf")]
    Pdf,
    #[serde(rename = "image/jpeg")]
    #[strum(serialize = "image/jpeg")]
    Jpeg,
    #[serde(rename = "image/png")]
    #[strum(serialize = "image/png")]
    Png,
    #[serde(rename = "image/svg+xml")]
    #[strum(serialize = "image/svg+xml")]
    Svg,
    #[serde(rename = "image/x-adobe-dng")]
    #[strum(serialize = "image/x-adobe-dng")]
    Dng,
    #[serde(rename = "jsonc")]
    #[strum(serialize = "jsonc")]
    Jsonc,
    #[serde(rename = "xml")]
    #[strum(serialize = "xml")]
    Xml,
    #[serde(rename = "md")]
    #[strum(serialize = "md")]
    Md,
}

#[derive(Serialize, Tsify)]
#[serde(rename_all = "camelCase")]
pub struct C2PAThumbnail {
    pub format: String,
    pub data: serde_bytes::ByteBuf,
}

#[derive(Serialize, Tsify)]
#[serde(rename_all = "camelCase")]
pub struct C2PAIngredient {
    pub manifest_id: Option<String>,
}

#[derive(Serialize, Tsify)]
#[serde(rename_all = "camelCase")]
pub struct RecognizedManifest {
    pub id: String,
    pub title: Option<String>,
    pub claim_generator: Option<String>,
    pub instance_id: String,
    pub signature_info: Option<serde_json::Value>,
    pub assertions: HashMap<String, serde_json::Value>,
    pub credentials: Vec<serde_json::Value>,
    pub thumbnail: Option<C2PAThumbnail>,
    pub ingredients: Vec<C2PAIngredient>,
}

#[derive(Serialize, Tsify)]
pub struct ManifestJson {
    pub claim_generator: Option<String>,
    pub claim_generator_info: Option<serde_json::Value>,
    pub title: Option<String>,
    pub instance_id: String,
    pub signature_info: Option<serde_json::Value>,
}

#[derive(Serialize, Tsify)]
pub struct ManifestStoreJson {
    pub active_manifest: Option<String>,
    pub manifests: HashMap<String, ManifestJson>,
}

#[derive(Serialize, Tsify)]
#[serde(rename_all = "camelCase")]
pub struct VerificationOutcome {
    pub state: bool,
    pub manifests: Vec<RecognizedManifest>,
    pub manifest_store: Option<ManifestStoreJson>,
}

#[derive(Serialize, Deserialize, Tsify)]
#[tsify(from_wasm_abi)]
pub enum SigningAlg {
    #[serde(rename = "es256")]
    Es256,
    #[serde(rename = "es384")]
    Es384,
    #[serde(rename = "es512")]
    Es512,
    #[serde(rename = "ps256")]
    Ps256,
    #[serde(rename = "ps384")]
    Ps384,
    #[serde(rename = "ps512")]
    Ps512,
    #[serde(rename = "ed25519")]
    Ed25519,
}

impl From<SigningAlg> for c2pa::crypto::raw_signature::SigningAlg {
    fn from(alg: SigningAlg) -> Self {
        match alg {
            SigningAlg::Es256 => c2pa::crypto::raw_signature::SigningAlg::Es256,
            SigningAlg::Es384 => c2pa::crypto::raw_signature::SigningAlg::Es384,
            SigningAlg::Es512 => c2pa::crypto::raw_signature::SigningAlg::Es512,
            SigningAlg::Ps256 => c2pa::crypto::raw_signature::SigningAlg::Ps256,
            SigningAlg::Ps384 => c2pa::crypto::raw_signature::SigningAlg::Ps384,
            SigningAlg::Ps512 => c2pa::crypto::raw_signature::SigningAlg::Ps512,
            SigningAlg::Ed25519 => c2pa::crypto::raw_signature::SigningAlg::Ed25519,
        }
    }
}

#[wasm_bindgen]
pub struct C2PASignResult {
    signed_asset: Vec<u8>,
    manifest: Vec<u8>,
}

#[wasm_bindgen]
impl C2PASignResult {
    #[wasm_bindgen(getter, js_name = "signedAsset")]
    pub fn signed_asset(&self) -> Vec<u8> {
        self.signed_asset.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn manifest(&self) -> Vec<u8> {
        self.manifest.clone()
    }
}

#[wasm_bindgen]
pub async fn sign_asset(
    format: SupportedFormat,
    asset: Vec<u8>,
    manifest_definition: JsValue,
    signcert: Vec<u8>,
    pkey: Vec<u8>,
    alg: SigningAlg,
    tsa_url: Option<String>,
) -> Result<C2PASignResult, JsValue> {
    let manifest_definition_json: serde_json::Value = serde_wasm_bindgen::from_value(manifest_definition)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let context = Context::new();
    let mut builder = c2pa::Builder::from_context(context)
        .with_definition(manifest_definition_json)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let signer = c2pa::create_signer::from_keys(&signcert, &pkey, alg.into(), tsa_url)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let mut source = Cursor::new(asset);
    let mut dest = Cursor::new(Vec::new());

    let manifest = builder.sign(signer.as_ref(), format.into(), &mut source, &mut dest)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    Ok(C2PASignResult {
        signed_asset: dest.into_inner(),
        manifest,
    })
}

#[wasm_bindgen]
pub async fn verify_asset(
    format: SupportedFormat,
    asset: Vec<u8>,
    trusted_certificates: Vec<String>,
) -> Result<JsValue, JsValue> {
    console_error_panic_hook::set_once();
    let outcome = internal_verify(format, asset, &trusted_certificates)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    use serde::Serialize as _;
    outcome.serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

async fn internal_verify(
    format: SupportedFormat,
    asset: Vec<u8>,
    trusted_certificates: &[String],
) -> c2pa::Result<VerificationOutcome> {
    let mut settings = Settings::new().with_value("verify.verify_trust", false)?;
    settings.core.decode_identity_assertions = false;
    settings.trust.trust_anchors = if trusted_certificates.is_empty() {
        None
    } else {
        Some(trusted_certificates.join("\n"))
    };

    let context = Context::new().with_settings(settings)?;
    let reader = Reader::from_context(context)
        .with_stream_async(format.into(), Cursor::new(asset))
        .await?;

    let manifests = reader
        .manifests()
        .iter()
        .map(|(label, manifest)| {
            let thumbnail = manifest.thumbnail().map(|(format, bytes)| C2PAThumbnail {
                format: format.to_owned(),
                data: bytes.into_owned().into(),
            });

            let ingredients = manifest
                .ingredients()
                .iter()
                .map(|ingredient| C2PAIngredient {
                    manifest_id: ingredient.active_manifest().map(ToOwned::to_owned),
                })
                .collect();

            let assertions = manifest
                .assertions()
                .iter()
                .filter_map(|assertion| {
                    let value = assertion.value().ok()?.clone();
                    Some((assertion.label().to_owned(), value))
                })
                .collect();

            let credentials = manifest
                .find_assertion(CREDENTIALS_ASSERTION_LABEL)
                .unwrap_or_default();

            RecognizedManifest {
                id: label.to_owned(),
                title: manifest.title().map(ToOwned::to_owned),
                claim_generator: manifest.claim_generator.clone(),
                instance_id: manifest.instance_id().to_owned(),
                signature_info: manifest.signature_info().and_then(|si| serde_json::to_value(si).ok()),
                assertions,
                credentials,
                thumbnail,
                ingredients,
            }
        })
        .collect();

    Ok(VerificationOutcome {
        state: matches!(reader.validation_state(), ValidationState::Trusted),
        manifests,
        manifest_store: {
            // reader.json() fails when any assertion contains serde_cbor::Value
            // with integer keys. Build a safe representation using typed structs.
            let manifests_map: HashMap<String, ManifestJson> = reader
                .manifests()
                .iter()
                .map(|(label, manifest)| {
                    let m = ManifestJson {
                        claim_generator: manifest.claim_generator().map(ToOwned::to_owned),
                        claim_generator_info: serde_json::to_value(&manifest.claim_generator_info).ok(),
                        title: manifest.title().map(ToOwned::to_owned),
                        instance_id: manifest.instance_id().to_owned(),
                        signature_info: manifest.signature_info().and_then(|si| serde_json::to_value(si).ok()),
                    };
                    (label.clone(), m)
                })
                .collect();
            Some(ManifestStoreJson {
                active_manifest: reader.active_label().map(ToOwned::to_owned),
                manifests: manifests_map,
            })
        },
    })
}
