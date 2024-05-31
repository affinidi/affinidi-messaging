use crate::errors::ATMError;
use did_peer::DIDPeer;
use didcomm::{
    did::{
        DIDCommMessagingService, DIDDoc, Service, VerificationMaterial, VerificationMethod,
        VerificationMethodType,
    },
    secrets::Secret,
};
use serde_json::{json, Value};
use ssi::did::Document;

/// Helper functions for converting between different types.

/// Converts from a SSI `Document` to Didcomm;s `DIDDoc`
/// Handles internal challenges such as expanding keys and converting to the correct format
pub(crate) async fn convert_did_format(doc: &Document) -> Result<DIDDoc, ATMError> {
    let doc = if doc.id.starts_with("did:peer:") {
        DIDPeer::expand_keys(doc).await.map_err(|e| {
            ATMError::DIDError(format!(
                "Couldn't expand the keys in the DID Document: {}. Error: {}",
                doc.id, e
            ))
        })?
    } else {
        doc.to_owned()
    };

    let mut new_doc = DIDDoc {
        id: doc.id.clone(),
        verification_method: vec![],
        authentication: vec![],
        key_agreement: vec![],
        service: vec![],
    };

    // Convert verificationMethod
    if let Some(verification_methods) = &doc.verification_method {
        for method in verification_methods {
            match method {
                ssi::did::VerificationMethod::Map(map) => {
                    new_doc.verification_method.push(VerificationMethod {
                        id: [doc.id.clone(), map.id.clone()].concat(),
                        type_: VerificationMethodType::JsonWebKey2020,
                        controller: [map.controller.clone(), map.id.clone()].concat(),
                        verification_material: VerificationMaterial::JWK {
                            public_key_jwk: json!(map.public_key_jwk.clone().unwrap()),
                        },
                    });
                }
                _ => {
                    return Err(ATMError::DIDError(
                        "Unknown verification method type".into(),
                    ))
                }
            }
        }
    } else {
        return Err(ATMError::DIDError(
            "missing verificationMethod in DID Document".into(),
        ));
    }

    // Convert keyAgreement
    if let Some(key_agreement) = &doc.key_agreement {
        for key_agreement in key_agreement {
            match key_agreement {
                ssi::did::VerificationMethod::DIDURL(url) => new_doc
                    .key_agreement
                    .push([doc.id.clone(), url.did.clone()].concat()),
                _ => return Err(ATMError::DIDError("Unknown keyAgreement".into())),
            }
        }
    } else {
        return Err(ATMError::DIDError(
            "missing keyAgreement in DID Document".into(),
        ));
    }

    // Convert authentication
    if let Some(authentication) = &doc.authentication {
        for authentication in authentication {
            match authentication {
                ssi::did::VerificationMethod::DIDURL(url) => new_doc
                    .authentication
                    .push([doc.id.clone(), url.did.clone()].concat()),
                _ => return Err(ATMError::DIDError("Unknown authentication".into())),
            }
        }
    } else {
        return Err(ATMError::DIDError(
            "missing authentication in DID Document".into(),
        ));
    }

    // Convert service
    if let Some(service) = &doc.service {
        for service in service {
            let a = match service
                .service_endpoint
                .clone()
                .unwrap()
                .first()
                .unwrap()
                .clone()
            {
                ssi::did::ServiceEndpoint::Map(value) => value,
                _ => return Err(ATMError::DIDError("Unknown service endpoint".into())),
            };

            let s = Service {
                id: service.id.clone(),
                service_endpoint: didcomm::did::ServiceKind::DIDCommMessaging {
                    value: DIDCommMessagingService {
                        uri: a.get("uri").unwrap().to_string(),
                        accept: a.get("accept").map(|v| {
                            v.as_array()
                                .unwrap()
                                .iter()
                                .map(|v| v.to_string().replace('"', ""))
                                .collect()
                        }),
                        routing_keys: a
                            .get("routing_keys")
                            .map(|v| {
                                v.as_array()
                                    .unwrap()
                                    .iter()
                                    .map(|v| v.to_string().replace('"', ""))
                                    .collect()
                            })
                            .unwrap_or_default(),
                    },
                },
            };
            new_doc.service.push(s);
        }
    } else {
        return Err(ATMError::DIDError("missing service in DID Document".into()));
    }

    Ok(new_doc)
}

/// Create a new Secret from a JWK JSON string
/// Example:
/// ```
/// let key_id = "did:example:123#key-1";
/// let key_str = r#"{
///    "crv": "Ed25519",
///    "d": "LLWCf...dGpIqSFw",
///    "kty": "OKP",
///    "x": "Hn8T...ZExwQo"
///  }"#;
///
/// let secret = Secret::from_str(key_id, key_str)?;
/// atm.add_secret(secret);
/// ```
pub fn secret_from_str(key_id: &str, jwk: &Value) -> Secret {
    Secret {
        id: key_id.to_string(),
        type_: didcomm::secrets::SecretType::JsonWebKey2020,
        secret_material: didcomm::secrets::SecretMaterial::JWK {
            private_key_jwk: jwk.clone(),
        },
    }
}
