// Converts from SSI DID Document to the DIDComm DID document format

use serde_json::json;
use ssi::did::Document;

use crate::{
    did::{
        DIDCommMessagingService, DIDDoc, Service, VerificationMaterial, VerificationMethod,
        VerificationMethodType,
    },
    error::{err_msg, ErrorKind, Result},
};

pub fn convert_did(did_doc: &Document) -> Result<DIDDoc> {
    let mut new_doc = DIDDoc {
        id: did_doc.id.clone(),
        verification_method: vec![],
        authentication: vec![],
        key_agreement: vec![],
        service: vec![],
    };

    // Convert verificationMethod
    if let Some(verification_methods) = &did_doc.verification_method {
        for method in verification_methods {
            match method {
                ssi::did::VerificationMethod::Map(map) => {
                    new_doc.verification_method.push(VerificationMethod {
                        id: [did_doc.id.clone(), map.id.clone()].concat(),
                        type_: VerificationMethodType::JsonWebKey2020,
                        controller: [map.controller.clone(), map.id.clone()].concat(),
                        verification_material: VerificationMaterial::JWK {
                            public_key_jwk: json!(map.public_key_jwk.clone().unwrap()),
                        },
                    });
                }
                _ => {
                    return Err(err_msg(
                        ErrorKind::Malformed,
                        "Unknown verification method type",
                    ))
                }
            }
        }
    } else {
        return Err(err_msg(
            ErrorKind::Malformed,
            "missing verificationMethod in DID Document",
        ));
    }

    // Convert keyAgreement
    if let Some(key_agreement) = &did_doc.key_agreement {
        for key_agreement in key_agreement {
            match key_agreement {
                ssi::did::VerificationMethod::DIDURL(url) => new_doc
                    .key_agreement
                    .push([did_doc.id.clone(), url.did.clone()].concat()),
                _ => return Err(err_msg(ErrorKind::Malformed, "Unknown keyAgreement")),
            }
        }
    } else {
        return Err(err_msg(
            ErrorKind::Malformed,
            "missing keyAgreement in DID Document",
        ));
    }

    // Convert authentication
    if let Some(authentication) = &did_doc.authentication {
        for authentication in authentication {
            match authentication {
                ssi::did::VerificationMethod::DIDURL(url) => new_doc
                    .authentication
                    .push([did_doc.id.clone(), url.did.clone()].concat()),
                _ => return Err(err_msg(ErrorKind::Malformed, "Unknown authentication")),
            }
        }
    } else {
        return Err(err_msg(
            ErrorKind::Malformed,
            "missing authentication in DID Document",
        ));
    }

    // Convert service
    if let Some(service) = &did_doc.service {
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
                _ => return Err(err_msg(ErrorKind::Malformed, "Unknown service endpoint")),
            };

            let s = Service {
                id: service.id.clone(),
                service_endpoint: crate::did::ServiceKind::DIDCommMessaging {
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
        return Err(err_msg(
            ErrorKind::Malformed,
            "missing authentication in DID Document",
        ));
    }

    Ok(new_doc)
}
