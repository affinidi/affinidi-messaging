//! Methods relating to working with DID's

use affinidi_did_resolver_cache_sdk::{config::ClientConfigBuilder, DIDCacheClient};
use affinidi_messaging_didcomm::secrets::{Secret, SecretMaterial, SecretType};
use did_peer::{
    DIDPeer, DIDPeerCreateKeys, DIDPeerKeys, DIDPeerService, PeerServiceEndPoint,
    PeerServiceEndPointLong,
};
use serde_json::json;
use ssi::{
    dids::{document::service::Endpoint, DIDBuf, DIDKey},
    jwk::Params,
    JWK,
};
use std::error::Error;
struct LocalDidPeerKeys {
    v_d: Option<String>,
    v_x: Option<String>,
    e_d: Option<String>,
    e_x: Option<String>,
    e_y: Option<String>,
}

/// Creates a fully formed DID, with corresponding secrets
/// - service: Creates a service definition with the provided URI if Some
///   - [0] = URI
pub fn create_did(service: Option<String>) -> Result<(String, Vec<Secret>), Box<dyn Error>> {
    // Generate keys for encryption and verification
    let v_ed25519_key = JWK::generate_ed25519().unwrap();

    let e_secp256k1_key = JWK::generate_secp256k1();

    let mut local_did_peer_keys = LocalDidPeerKeys {
        v_d: None,
        v_x: None,
        e_d: None,
        e_x: None,
        e_y: None,
    };

    if let Params::OKP(map) = v_ed25519_key.clone().params {
        local_did_peer_keys.v_d = Some(String::from(map.private_key.clone().unwrap()));
        local_did_peer_keys.v_x = Some(String::from(map.public_key.clone()));
    }

    if let Params::EC(map) = e_secp256k1_key.clone().params {
        local_did_peer_keys.e_d = Some(String::from(map.ecc_private_key.clone().unwrap()));
        local_did_peer_keys.e_x = Some(String::from(map.x_coordinate.clone().unwrap()));
        local_did_peer_keys.e_y = Some(String::from(map.y_coordinate.clone().unwrap()));
    }

    // Create the did:key DID's for each key above
    let v_did_key = DIDKey::generate(&v_ed25519_key).unwrap();
    let e_did_key = DIDKey::generate(&e_secp256k1_key).unwrap();

    // Put these keys in order and specify the type of each key (we strip the did:key: from the front)
    let keys = vec![
        DIDPeerCreateKeys {
            purpose: DIDPeerKeys::Verification,
            type_: None,
            public_key_multibase: Some(v_did_key[8..].to_string()),
        },
        DIDPeerCreateKeys {
            purpose: DIDPeerKeys::Encryption,
            type_: None,
            public_key_multibase: Some(e_did_key[8..].to_string()),
        },
    ];

    // Create a service definition
    let services = service.map(|service| {
        vec![DIDPeerService {
            id: None,
            _type: "dm".into(),
            service_end_point: PeerServiceEndPoint::Long(PeerServiceEndPointLong {
                uri: service,
                accept: vec!["didcomm/v2".into()],
                routing_keys: vec![],
            }),
        }]
    });

    let services = services.as_ref();

    // Create the did:peer DID
    let (did_peer, _) =
        DIDPeer::create_peer_did(&keys, services).expect("Failed to create did:peer");

    let secrets_json = vec![
        Secret {
            id: format!("{}#key-1", did_peer),
            type_: SecretType::JsonWebKey2020,
            secret_material: SecretMaterial::JWK {
                private_key_jwk: json!({
                    "crv": "Ed25519",
                    "d":  local_did_peer_keys.v_d,
                    "kty": "OKP",
                    "x": local_did_peer_keys.v_x
                }),
            },
        },
        Secret {
            id: format!("{}#key-2", did_peer),
            type_: SecretType::JsonWebKey2020,
            secret_material: SecretMaterial::JWK {
                private_key_jwk: json!({
                    "crv": "secp256k1",
                    "d": local_did_peer_keys.e_d,
                    "kty": "EC",
                    "x": local_did_peer_keys.e_x,
                    "y": local_did_peer_keys.e_y,
                }),
            },
        },
    ];

    Ok((did_peer, secrets_json))
}

/// Helper function to resolve a DID and retrieve the URI address of the service endpoint
pub async fn get_service_address(did: &str) -> Result<String, Box<dyn Error>> {
    let did_resolver = DIDCacheClient::new(ClientConfigBuilder::default().build()).await?;

    let resolve_response = did_resolver
        .resolve(DIDBuf::from_string(did.into())?.as_did())
        .await?;

    let uri = if let Some(service) = resolve_response.doc.service.first() {
        if let Some(end_point) = &service.service_endpoint {
            if let Some(endpoint) = end_point.first() {
                match endpoint {
                    Endpoint::Map(map) => {
                        if let Some(uri) = map.get("uri") {
                            uri.as_str()
                        } else {
                            None
                        }
                    }
                    Endpoint::Uri(uri) => Some(uri.as_str()),
                }
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    if let Some(uri) = uri {
        Ok(uri.replace('"', "").trim_end_matches('/').to_string())
    } else {
        Err("No service endpoint found".into())
    }
}
