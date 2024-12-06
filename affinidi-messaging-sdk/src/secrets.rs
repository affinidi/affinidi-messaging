/*!
Handles Secrets - mainly used for internal representation and for saving to files (should always be encrypted)

*/

use affinidi_messaging_didcomm::secrets::{
    Secret as DidcommSecret, SecretMaterial as DidcommSecretMaterial,
    SecretType as DidcommSecretType,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Secret {
    /// A key ID identifying a secret (private key).
    pub id: String,

    /// Must have the same semantics as type ('type' field) of the corresponding method in DID Doc containing a public key.
    #[serde(rename = "type")]
    pub type_: SecretType,

    /// Value of the secret (private key)
    #[serde(flatten)]
    pub secret_material: SecretMaterial,
}

impl From<Secret> for DidcommSecret {
    fn from(val: Secret) -> DidcommSecret {
        DidcommSecret {
            id: val.id,
            type_: val.type_.into(),
            secret_material: val.secret_material.into(),
        }
    }
}

/// Must have the same semantics as type ('type' field) of the corresponding method in DID Doc containing a public key.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum SecretType {
    JsonWebKey2020,
    X25519KeyAgreementKey2019,
    X25519KeyAgreementKey2020,
    Ed25519VerificationKey2018,
    Ed25519VerificationKey2020,
    EcdsaSecp256k1VerificationKey2019,
    Other,
}

impl From<SecretType> for DidcommSecretType {
    fn from(val: SecretType) -> DidcommSecretType {
        match val {
            SecretType::JsonWebKey2020 => DidcommSecretType::JsonWebKey2020,
            SecretType::X25519KeyAgreementKey2019 => DidcommSecretType::X25519KeyAgreementKey2019,
            SecretType::X25519KeyAgreementKey2020 => DidcommSecretType::X25519KeyAgreementKey2020,
            SecretType::Ed25519VerificationKey2018 => DidcommSecretType::Ed25519VerificationKey2018,
            SecretType::Ed25519VerificationKey2020 => DidcommSecretType::Ed25519VerificationKey2020,
            SecretType::EcdsaSecp256k1VerificationKey2019 => {
                DidcommSecretType::EcdsaSecp256k1VerificationKey2019
            }
            SecretType::Other => DidcommSecretType::Other,
        }
    }
}

/// Represents secret crypto material.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum SecretMaterial {
    #[serde(rename_all = "camelCase")]
    JWK { private_key_jwk: Value },

    #[serde(rename_all = "camelCase")]
    Multibase { private_key_multibase: String },

    #[serde(rename_all = "camelCase")]
    Base58 { private_key_base58: String },
}

impl From<SecretMaterial> for DidcommSecretMaterial {
    fn from(val: SecretMaterial) -> DidcommSecretMaterial {
        match val {
            SecretMaterial::JWK { private_key_jwk } => {
                DidcommSecretMaterial::JWK { private_key_jwk }
            }
            SecretMaterial::Multibase {
                private_key_multibase,
            } => DidcommSecretMaterial::Multibase {
                private_key_multibase,
            },
            SecretMaterial::Base58 { private_key_base58 } => {
                DidcommSecretMaterial::Base58 { private_key_base58 }
            }
        }
    }
}
