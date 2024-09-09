use affinidi_messaging_didcomm::secrets::Secret;
use serde_json::Value;

/// Helper functions for converting between different types.

/// Create a new Secret from a JWK JSON string
/// Example:
/// ```ignore
/// use affinidi_messaging_didcomm::secrets::Secret;
/// use affinidi_messaging_sdk::ATM;
/// use affinidi_messaging_sdk::config::Config;
/// use affinidi_messaging_sdk::conversations::secret_from_str;
/// 
/// let config = Config::builder().build()?;
/// let atm = ATM::new(config).await?;
/// 
/// let key_id = "did:example:123#key-1";
/// let key_str = r#"{
///    "crv": "Ed25519",
///    "d": "LLWCf...dGpIqSFw",
///    "kty": "OKP",
///    "x": "Hn8T...ZExwQo"
///  }"#;
///
/// let secret = secret_from_str(key_id, key_str)?;
/// atm.add_secret(secret);
/// ```
pub fn secret_from_str(key_id: &str, jwk: &Value) -> Secret {
    Secret {
        id: key_id.to_string(),
        type_: affinidi_messaging_didcomm::secrets::SecretType::JsonWebKey2020,
        secret_material: affinidi_messaging_didcomm::secrets::SecretMaterial::JWK {
            private_key_jwk: jwk.clone(),
        },
    }
}
