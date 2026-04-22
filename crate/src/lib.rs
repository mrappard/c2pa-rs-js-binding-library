use std::{collections::HashMap, io::Cursor};
use wasm_bindgen::prelude::*;
use c2pa::{Reader, ValidationState, settings::Settings};
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
    #[serde(rename = "image/x-adobe-dng")]
    #[strum(serialize = "image/x-adobe-dng")]
    Dng,
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
    pub assertions: HashMap<String, serde_json::Value>,
    pub credentials: Vec<serde_json::Value>,
    pub thumbnail: Option<C2PAThumbnail>,
    pub ingredients: Vec<C2PAIngredient>,
}

#[derive(Serialize, Tsify)]
#[serde(rename_all = "camelCase")]
pub struct VerificationOutcome {
    pub state: bool,
    pub manifests: Vec<RecognizedManifest>,
}

#[wasm_bindgen]
pub fn verify_asset(
    format: SupportedFormat,
    asset: &[u8],
    trusted_certificates: Vec<String>,
) -> Result<JsValue, JsValue> {
    let outcome = internal_verify(format, asset, &trusted_certificates)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    serde_wasm_bindgen::to_value(&outcome)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

fn internal_verify(
    format: SupportedFormat,
    asset: &[u8],
    trusted_certificates: &[String],
) -> c2pa::Result<VerificationOutcome> {
    let mut settings = Settings::default();
    settings.core.decode_identity_assertions = false;
    settings.trust.trust_anchors = if trusted_certificates.is_empty() {
        None
    } else {
        Some(trusted_certificates.join("\n"))
    };
    Settings::from_toml(&toml::to_string(&settings).unwrap()).unwrap();

    let reader = Reader::from_stream(format.into(), Cursor::new(asset))?;

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
    })
}
