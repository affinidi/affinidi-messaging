//! Helper functions to do with the Mediator
use base64::prelude::*;
use console::style;
use did_peer::{
    DIDPeer, DIDPeerCreateKeys, DIDPeerKeys, DIDPeerService, PeerServiceEndPoint,
    PeerServiceEndPointLong,
};
use regex::Regex;
use ring::signature::Ed25519KeyPair;
use serde_json::json;
use ssi::{dids::DIDKey, jwk::Params, JWK};
use std::{error::Error, fs::File, io::Write};

#[derive(Debug, Default)]
pub(crate) struct MediatorConfig {
    pub mediator_did: Option<String>,
    pub mediator_secrets: Option<String>,
    pub admin_did: Option<String>,
    pub admin_secrets: Option<String>,
    pub jwt_authorization_secret: Option<String>,
}

struct LocalDidPeerKeys {
    v_d: Option<String>,
    v_x: Option<String>,
    e_d: Option<String>,
    e_x: Option<String>,
    e_y: Option<String>,
}

impl MediatorConfig {
    /// Creates a fully formed DID, with corresponding secrets
    /// - service: if true, a service definition is created
    pub(crate) fn create_did(&mut self, service: bool) -> Result<(String, String), Box<dyn Error>> {
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
        let services = if service {
            Some(vec![DIDPeerService {
                id: None,
                _type: "dm".into(),
                service_end_point: PeerServiceEndPoint::Long(PeerServiceEndPointLong {
                    uri: "https://localhost:7037/".into(),
                    accept: vec!["didcomm/v2".into()],
                    routing_keys: vec![],
                }),
            }])
        } else {
            None
        };

        let services = services.as_ref();

        // Create the did:peer DID
        let (did_peer, _) =
            DIDPeer::create_peer_did(&keys, services).expect("Failed to create did:peer");

        let secrets_json = json!([
          {
              "id": format!("{}#key-1", did_peer),
              "type": "JsonWebKey2020",
              "privateKeyJwk": {
                  "crv": "Ed25519",
                  "d":  local_did_peer_keys.v_d,
                  "kty": "OKP",
                  "x": local_did_peer_keys.v_x
              }
          },
          {
              "id": format!("{}#key-2", did_peer),
              "type": "JsonWebKey2020",
              "privateKeyJwk": {
                  "crv": "secp256k1",
                  "d": local_did_peer_keys.e_d,
                  "kty": "EC",
                  "x": local_did_peer_keys.e_x,
                  "y": local_did_peer_keys.e_y,
              }
          }
        ]);

        let mediator_secrets = serde_json::to_string_pretty(&secrets_json)?;

        Ok((did_peer, mediator_secrets))
    }

    pub fn create_jwt_secrets(&mut self) -> Result<(), Box<dyn Error>> {
        // Create jwt_authorization_secret
        self.jwt_authorization_secret = Some(
            BASE64_URL_SAFE_NO_PAD
                .encode(Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap()),
        );

        println!(
            "  {} {}",
            style(" JWT Authorization Secret created: ").blue().bold(),
            style(&self.jwt_authorization_secret.as_ref().unwrap()).color256(208)
        );

        Ok(())
    }

    /// Saves a mediator configuration to a file
    pub fn save_config(&self) -> Result<(), Box<dyn Error>> {
        // 1. Write out the mediator secrets file
        if let Some(secrets) = &self.mediator_secrets {
            let mut file = File::create("./affinidi-messaging-mediator/conf/secrets.json")?;
            file.write_all(secrets.as_bytes())?;
            file.flush()?;
            println!(
                "  {}{}{}",
                style("Mediator secrets file (").blue(),
                style("./affinidi-messaging-mediator/conf/secrets.json").color256(201),
                style(") written...").blue()
            );
        }

        // 2. Write out the admin secrets file
        if let Some(secrets) = &self.admin_secrets {
            let mut file = File::create("./affinidi-messaging-mediator/conf/secrets-admin.json")?;
            file.write_all(secrets.as_bytes())?;
            file.flush()?;
            println!(
                "  {}{}{}",
                style("Administration secrets file (").blue(),
                style("./affinidi-messaging-mediator/conf/secrets-admin.json").color256(201),
                style(") written...").blue()
            );
        }

        // 3. Write out changes ot the mediator configuration file
        let config = std::fs::read_to_string("./affinidi-messaging-mediator/conf/mediator.toml")?;
        let mut new_config = String::new();
        let mut change_flag = false;

        let mediator_did_re = Regex::new(r"^mediator_did\s*=").unwrap();
        let admin_did_re = Regex::new(r"^admin_did\s*=").unwrap();
        let jwt_authorization_re = Regex::new(r"^jwt_authorization_secret\s*=").unwrap();
        config.lines().for_each(|line| {
            if mediator_did_re.is_match(line) {
                if let Some(mediator_did) = &self.mediator_did {
                    let new_str = format!(
                        "mediator_did = \"${{MEDIATOR_DID:did://{}}}\"",
                        mediator_did
                    );
                    new_config.push_str(&new_str);
                    new_config.push('\n');
                    println!(
                        "  {} {}",
                        style("Line modified:").blue(),
                        style(&new_str).color256(208),
                    );
                    change_flag = true;
                } else {
                    new_config.push_str(line);
                    new_config.push('\n');
                }
            } else if admin_did_re.is_match(line) {
                if let Some(admin_did) = &self.admin_did {
                    let new_str = format!("admin_did = \"${{ADMIN_DID:did://{}}}\"", admin_did);
                    new_config.push_str(&new_str);
                    new_config.push('\n');
                    println!(
                        "  {} {}",
                        style("Line modified:").blue(),
                        style(&new_str).color256(208),
                    );
                    change_flag = true;
                } else {
                    new_config.push_str(line);
                    new_config.push('\n');
                }
            } else if jwt_authorization_re.is_match(line) {
                if let Some(jwt_auth) = &self.jwt_authorization_secret {
                    let new_str = format!(
                        "jwt_authorization_secret = \"${{JWT_AUTHORIZATION_SECRET:string://{}}}\"",
                        jwt_auth
                    );
                    new_config.push_str(&new_str);
                    new_config.push('\n');
                    println!(
                        "  {} {}",
                        style("Line modified:").blue(),
                        style(&new_str).color256(208),
                    );
                    change_flag = true;
                } else {
                    new_config.push_str(line);
                    new_config.push('\n');
                }
            } else {
                new_config.push_str(line);
                new_config.push('\n');
            }
        });

        if change_flag {
            std::fs::write(
                "./affinidi-messaging-mediator/conf/mediator.toml",
                new_config,
            )?;

            println!(
                "  {}{}{}",
                style("Mediator configuration file (").blue(),
                style("./affinidi-messaging-mediator/conf/mediator.toml").color256(201),
                style(") updated...").blue(),
            );
        } else {
            println!(
                "  {}",
                style("No changes were made to the Mediator Configuration").blue(),
            );
        }

        Ok(())
    }
}
