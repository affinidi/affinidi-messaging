//! Representation of a contact in the client
use crate::messages::Message;
use affinidi_messaging_sdk::{
    profiles::ProfileConfig,
    secrets::{Secret, SecretMaterial, SecretType},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use ssi::{dids::DIDKey, jwk::Params, JWK};
use std::time::Duration;
use tracing::info;

/// State of the contact
/// NotUsed: Contact has not been used yet
/// InviteSent: An invite has been sent from the contact (with the time it was sent)
/// InviteResponded: The invite has been responded to (with the time it was responded to)
/// Established: The contact has been established with a remote party
#[derive(Default, Serialize, Deserialize)]
pub enum ContactState {
    #[default]
    NotUsed,
    InviteSent(Duration),
    InviteResponded(Duration),
    Established,
}

#[derive(Default, Serialize, Deserialize)]
pub(crate) struct Contact {
    pub alias: String,
    pub avatar: Option<String>, // BASE64 encoded image
    pub remote_did: Option<String>,
    pub our_profile: ProfileConfig,
    pub messages: Vec<Message>,
    pub state: ContactState,
}

fn _create_did() -> (String, Secret) {
    let p256_key = JWK::generate_p256();
    let did_key = DIDKey::generate(&p256_key).unwrap();

    let (d, x, y) = if let Params::EC(map) = p256_key.clone().params {
        (
            String::from(map.ecc_private_key.clone().unwrap()),
            String::from(map.x_coordinate.clone().unwrap()),
            String::from(map.y_coordinate.clone().unwrap()),
        )
    } else {
        panic!("Failed to generate P256 key")
    };

    info!("Created new DID: {}", did_key);

    let secret = Secret {
        id: format!("{}#key-1", did_key),
        type_: SecretType::JsonWebKey2020,
        secret_material: SecretMaterial::JWK {
            private_key_jwk: json!({
                "crv": "P256",
                "d":  d,
                "kty": "EC",
                "x": x,
                "y": y
            }),
        },
    };

    (did_key.to_string(), secret)
}

impl Contact {
    pub fn new_with_invite(alias: String, mediator: &str) -> Self {
        let (did, secret) = _create_did();
        Contact {
            alias: alias.clone(),
            our_profile: ProfileConfig {
                alias: alias.clone(),
                did,
                secrets: vec![secret],
                mediator: Some(mediator.to_string()),
            },
            ..Default::default()
        }
    }
}
