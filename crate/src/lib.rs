use std::{
    collections::HashMap,
    io::Cursor,
    sync::{Arc, Mutex},
};

use c2pa::{
    settings::Settings,
    Context, Reader, ValidationState,
};
use serde::{Deserialize, Serialize};
use strum::{EnumString, IntoStaticStr};
use tsify::Tsify;
use wasm_bindgen::prelude::*;

const CREDENTIALS_ASSERTION_LABEL: &str = "io.vaultie.credentials";
const IDENTITY_ASSERTION_PREFIX: &str = "cawg.identity";

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
#[derive(Copy, Clone, Debug)]
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

#[derive(Serialize, Deserialize, Tsify)]
#[serde(rename_all = "camelCase")]
#[tsify(from_wasm_abi)]
pub struct IdentityAssertionOptions {
    pub sig_type: String,
    pub reserve_size: usize,
    #[serde(default)]
    pub referenced_assertions: Vec<String>,
    #[serde(default)]
    pub roles: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PreparedIdentityAssertionState {
    format: SupportedFormat,
    asset: serde_bytes::ByteBuf,
    manifest_definition: serde_json::Value,
    signcert: serde_bytes::ByteBuf,
    pkey: serde_bytes::ByteBuf,
    alg: SigningAlg,
    tsa_url: Option<String>,
    options: IdentityAssertionOptions,
    signer_payload: serde_json::Value,
    signer_payload_cbor: serde_bytes::ByteBuf,
}

#[derive(Serialize, Tsify)]
#[serde(rename_all = "camelCase")]
pub struct IdentityAssertionRecord {
    pub label: String,
    pub validated: bool,
    pub data: serde_json::Value,
}

#[derive(Serialize, Tsify)]
#[serde(rename_all = "camelCase")]
pub struct IdentityAssertionVerificationOutcome {
    pub manifests: HashMap<String, Vec<IdentityAssertionRecord>>,
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

#[derive(Default)]
struct CapturedSignerPayload {
    payload_json: Option<serde_json::Value>,
    payload_cbor: Option<Vec<u8>>,
}

struct PrepareIdentityAssertionCredentialHolder {
    sig_type: String,
    reserve_size: usize,
    captured: Arc<Mutex<CapturedSignerPayload>>,
}

impl c2pa::identity::builder::CredentialHolder for PrepareIdentityAssertionCredentialHolder {
    fn sig_type(&self) -> &'static str {
        Box::leak(self.sig_type.clone().into_boxed_str())
    }

    fn reserve_size(&self) -> usize {
        self.reserve_size
    }

    fn sign(
        &self,
        signer_payload: &c2pa::identity::SignerPayload,
    ) -> Result<Vec<u8>, c2pa::identity::builder::IdentityBuilderError> {
        let payload_json = serde_json::to_value(signer_payload)
            .map_err(|err| c2pa::identity::builder::IdentityBuilderError::SignerError(err.to_string()))?;
        let mut payload_cbor = Vec::new();
        c2pa_cbor::to_writer(&mut payload_cbor, signer_payload)
            .map_err(|err| c2pa::identity::builder::IdentityBuilderError::CborGenerationError(err.to_string()))?;

        let mut captured = self
            .captured
            .lock()
            .map_err(|_| c2pa::identity::builder::IdentityBuilderError::InternalError("identity assertion state lock poisoned".to_string()))?;
        captured.payload_json = Some(payload_json);
        captured.payload_cbor = Some(payload_cbor);

        // Return a minimal placeholder signature so the internal C2PA build can
        // complete and the captured signer payload reflects the finalized
        // content-binding state.
        Ok(vec![0u8])
    }
}

struct FinalizeIdentityAssertionCredentialHolder {
    sig_type: String,
    reserve_size: usize,
    signature: Vec<u8>,
}

impl c2pa::identity::builder::CredentialHolder for FinalizeIdentityAssertionCredentialHolder {
    fn sig_type(&self) -> &'static str {
        Box::leak(self.sig_type.clone().into_boxed_str())
    }

    fn reserve_size(&self) -> usize {
        self.reserve_size
    }

    fn sign(
        &self,
        _signer_payload: &c2pa::identity::SignerPayload,
    ) -> Result<Vec<u8>, c2pa::identity::builder::IdentityBuilderError> {
        Ok(self.signature.clone())
    }
}

fn serialize_to_js<T: Serialize>(value: &T) -> Result<JsValue, JsValue> {
    value
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|err| JsValue::from_str(&err.to_string()))
}

// Like serialize_to_js but keeps byte fields as Uint8Array rather than plain
// arrays of numbers. json_compatible() sets serialize_bytes_as_arrays:true which
// makes Uint8Array impossible to round-trip through serde_wasm_bindgen::from_value.
fn serialize_state_to_js<T: Serialize>(value: &T) -> Result<JsValue, JsValue> {
    value
        .serialize(
            &serde_wasm_bindgen::Serializer::new()
                .serialize_maps_as_objects(true),
        )
        .map_err(|err| JsValue::from_str(&err.to_string()))
}

fn stabilize_manifest_definition(manifest_definition: &mut serde_json::Value) {
    if let Some(object) = manifest_definition.as_object_mut() {
        if !object.contains_key("instance_id") {
            object.insert(
                "instance_id".to_string(),
                serde_json::Value::String(format!("xmp:iid:{}", uuid::Uuid::new_v4())),
            );
        }
        // Stabilize the manifest label so referenced_assertion URLs are identical
        // across the prepare and finalize calls. Without this, Claim::new() generates
        // a fresh UUID each invocation, making the SignerPayload non-deterministic.
        if !object.contains_key("label") {
            object.insert(
                "label".to_string(),
                serde_json::Value::String(format!("urn:c2pa:{}", uuid::Uuid::new_v4())),
            );
        }
    }
}

fn build_identity_sign_result<CH: c2pa::identity::builder::CredentialHolder + Send + Sync + 'static>(
    format: SupportedFormat,
    asset: Vec<u8>,
    manifest_definition: serde_json::Value,
    signcert: Vec<u8>,
    pkey: Vec<u8>,
    alg: SigningAlg,
    tsa_url: Option<String>,
    options: &IdentityAssertionOptions,
    credential_holder: CH,
) -> Result<C2PASignResult, JsValue> {
    let context = Context::new();
    let mut builder = c2pa::Builder::from_context(context)
        .with_definition(manifest_definition)
        .map_err(|err| JsValue::from_str(&err.to_string()))?;

    let raw_signer = c2pa::crypto::raw_signature::signer_from_cert_chain_and_private_key(
        &signcert,
        &pkey,
        alg.into(),
        tsa_url,
    )
    .map_err(|err| JsValue::from_str(&err.to_string()))?;

    let mut signer = c2pa::identity::builder::IdentityAssertionSigner::new(raw_signer);
    let mut identity_builder =
        c2pa::identity::builder::IdentityAssertionBuilder::for_credential_holder(credential_holder);

    if !options.referenced_assertions.is_empty() {
        let referenced_assertions: Vec<&str> = options
            .referenced_assertions
            .iter()
            .map(String::as_str)
            .collect();
        identity_builder.add_referenced_assertions(&referenced_assertions);
    }

    if !options.roles.is_empty() {
        let roles: Vec<&str> = options.roles.iter().map(String::as_str).collect();
        identity_builder.add_roles(&roles);
    }

    signer.add_identity_assertion(identity_builder);

    let mut source = Cursor::new(asset);
    let mut dest = Cursor::new(Vec::new());

    let manifest = builder
        .sign(&signer, format.into(), &mut source, &mut dest)
        .map_err(|err| JsValue::from_str(&err.to_string()))?;

    Ok(C2PASignResult {
        signed_asset: dest.into_inner(),
        manifest,
    })
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
pub async fn prepare_identity_assertion(
    format: SupportedFormat,
    asset: Vec<u8>,
    manifest_definition: JsValue,
    signcert: Vec<u8>,
    pkey: Vec<u8>,
    alg: SigningAlg,
    tsa_url: Option<String>,
    options: JsValue,
) -> Result<JsValue, JsValue> {
    let mut manifest_definition_json: serde_json::Value = serde_wasm_bindgen::from_value(manifest_definition)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    stabilize_manifest_definition(&mut manifest_definition_json);
    let options: IdentityAssertionOptions = serde_wasm_bindgen::from_value(options)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let captured = Arc::new(Mutex::new(CapturedSignerPayload::default()));
    let holder = PrepareIdentityAssertionCredentialHolder {
        sig_type: options.sig_type.clone(),
        reserve_size: options.reserve_size,
        captured: Arc::clone(&captured),
    };

    build_identity_sign_result(
        format,
        asset.clone(),
        manifest_definition_json.clone(),
        signcert.clone(),
        pkey.clone(),
        alg,
        tsa_url.clone(),
        &options,
        holder,
    )?;

    let captured = captured
        .lock()
        .map_err(|_| JsValue::from_str("identity assertion state lock poisoned"))?;

    let signer_payload = captured
        .payload_json
        .clone()
        .ok_or_else(|| JsValue::from_str("failed to capture signer payload"))?;
    let signer_payload_cbor = captured
        .payload_cbor
        .clone()
        .ok_or_else(|| JsValue::from_str("failed to capture signer payload bytes"))?;

    let state = PreparedIdentityAssertionState {
        format,
        asset: asset.into(),
        manifest_definition: manifest_definition_json,
        signcert: signcert.into(),
        pkey: pkey.into(),
        alg,
        tsa_url,
        options,
        signer_payload,
        signer_payload_cbor: signer_payload_cbor.into(),
    };

    serialize_state_to_js(&state)
}

#[wasm_bindgen]
pub async fn finalize_identity_assertion(
    prepared_state: JsValue,
    signature: Vec<u8>,
) -> Result<C2PASignResult, JsValue> {
    let state: PreparedIdentityAssertionState = serde_wasm_bindgen::from_value(prepared_state)
        .map_err(|e| JsValue::from_str(&format!("failed to deserialize prepared state: {e}")))?;

    let holder = FinalizeIdentityAssertionCredentialHolder {
        sig_type: state.options.sig_type.clone(),
        reserve_size: state.options.reserve_size,
        signature,
    };

    build_identity_sign_result(
        state.format,
        state.asset.into_vec(),
        state.manifest_definition,
        state.signcert.into_vec(),
        state.pkey.into_vec(),
        state.alg,
        state.tsa_url,
        &state.options,
        holder,
    )
}

#[wasm_bindgen]
pub async fn sign_asset_with_x509_identity(
    format: SupportedFormat,
    asset: Vec<u8>,
    manifest_definition: JsValue,
    signcert: Vec<u8>,
    pkey: Vec<u8>,
    alg: SigningAlg,
    identity_signcert: Vec<u8>,
    identity_pkey: Vec<u8>,
    identity_alg: SigningAlg,
    options: JsValue,
    tsa_url: Option<String>,
    identity_tsa_url: Option<String>,
) -> Result<C2PASignResult, JsValue> {
    let mut manifest_definition_json: serde_json::Value = serde_wasm_bindgen::from_value(manifest_definition)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    stabilize_manifest_definition(&mut manifest_definition_json);
    let options: IdentityAssertionOptions = serde_wasm_bindgen::from_value(options)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let identity_raw_signer = c2pa::crypto::raw_signature::signer_from_cert_chain_and_private_key(
        &identity_signcert,
        &identity_pkey,
        identity_alg.into(),
        identity_tsa_url,
    )
    .map_err(|err| JsValue::from_str(&err.to_string()))?;

    let holder = c2pa::identity::x509::X509CredentialHolder::from_raw_signer(identity_raw_signer);

    build_identity_sign_result(
        format,
        asset,
        manifest_definition_json,
        signcert,
        pkey,
        alg,
        tsa_url,
        &options,
        holder,
    )
}

#[wasm_bindgen]
pub fn sign_identity_assertion_payload_x509(
    signer_payload_cbor: Vec<u8>,
    signcert: Vec<u8>,
    pkey: Vec<u8>,
    alg: SigningAlg,
    tsa_url: Option<String>,
) -> Result<Vec<u8>, JsValue> {
    let raw_signer = c2pa::crypto::raw_signature::signer_from_cert_chain_and_private_key(
        &signcert,
        &pkey,
        alg.into(),
        tsa_url,
    )
    .map_err(|err| JsValue::from_str(&err.to_string()))?;

    c2pa::crypto::cose::sign(
        raw_signer.as_ref(),
        &signer_payload_cbor,
        None,
        c2pa::crypto::cose::TimeStampStorage::V2_sigTst2_CTT,
    )
    .map_err(|err| JsValue::from_str(&err.to_string()))
}

#[wasm_bindgen]
pub async fn verify_asset(
    format: SupportedFormat,
    asset: Vec<u8>,
    trusted_certificates: Vec<String>,
) -> Result<JsValue, JsValue> {
    console_error_panic_hook::set_once();
    let outcome = internal_verify(format, asset, &trusted_certificates, false)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    serialize_to_js(&outcome)
}

#[wasm_bindgen]
pub async fn verify_identity_assertions(
    format: SupportedFormat,
    asset: Vec<u8>,
    trusted_certificates: Vec<String>,
) -> Result<JsValue, JsValue> {
    console_error_panic_hook::set_once();
    let outcome = internal_verify(format, asset, &trusted_certificates, true)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let manifests = outcome
        .manifests
        .into_iter()
        .map(|manifest| {
            let identities = manifest
                .assertions
                .into_iter()
                .filter(|(label, _)| label == IDENTITY_ASSERTION_PREFIX || label.starts_with(&format!("{IDENTITY_ASSERTION_PREFIX}__")))
                .map(|(label, data)| {
                    let validated = data
                        .as_object()
                        .map(|obj| !obj.contains_key("signature"))
                        .unwrap_or(false);
                    IdentityAssertionRecord {
                        label,
                        validated,
                        data,
                    }
                })
                .collect();
            (manifest.id, identities)
        })
        .collect();

    serialize_to_js(&IdentityAssertionVerificationOutcome { manifests })
}

#[wasm_bindgen]
pub fn clean_asset(
    format: SupportedFormat,
    asset: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    match c2pa::jumbf_io::remove_jumbf_from_memory(format.into(), &asset) {
        Ok(cleaned) => Ok(cleaned),
        Err(c2pa::Error::JumbfNotFound) => Ok(asset),
        Err(err) => Err(JsValue::from_str(&err.to_string())),
    }
}

async fn internal_verify(
    format: SupportedFormat,
    asset: Vec<u8>,
    trusted_certificates: &[String],
    decode_identity_assertions: bool,
) -> c2pa::Result<VerificationOutcome> {
    let mut settings = Settings::new().with_value("verify.verify_trust", false)?;
    settings.core.decode_identity_assertions = decode_identity_assertions;
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
