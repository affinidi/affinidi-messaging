use affinidi_did_resolver_cache_sdk::{DIDCacheClient, document::DocumentExt};
use affinidi_secrets_resolver::SecretsResolver;
use serde::Serialize;

use crate::{
    Message,
    document::{did_or_url, is_did},
    error::{ErrorKind, Result, err_msg},
    jws::{self, Algorithm},
    utils::crypto::{AsKnownKeyPairSecret, KnownKeyPair},
};

impl Message {
    /// Produces `DIDComm Signed Message`
    /// https://identity.foundation/didcomm-messaging/spec/#didcomm-signed-message.
    ///
    /// Signed messages are not necessary to provide message integrity (tamper evidence),
    /// or to prove the sender to the recipient. Both of these guarantees automatically occur
    /// with the authenticated encryption in DIDComm encrypted messages. Signed messages are only
    /// necessary when the origin of plaintext must be provable to third parties,
    /// or when the sender can’t be proven to the recipient by authenticated encryption because
    /// the recipient is not known in advance (e.g., in a broadcast scenario).
    /// We therefore expect signed messages to be used in a few cases, but not as a matter of course.
    ///
    /// # Parameters
    /// - `sign_by` a DID or key ID the sender uses for signing
    /// - `did_resolver` instance of `DIDResolver` to resolve DIDs.
    /// - `secrets_resolver` instance of SecretsResolver` to resolve sender DID keys secrets
    ///
    /// # Returns
    /// Tuple (signed_message, metadata)
    /// - `signed_message` a DIDComm signed message as JSON string
    /// - `metadata` additional metadata about this `encrypt` execution like used keys identifiers and algorithms.
    ///
    /// # Errors
    /// - `DIDNotResolved` Sender or recipient DID not found.
    /// - `DIDUrlNotFound` DID doesn't contain mentioned DID Urls (for ex., key id)
    /// - `SecretNotFound` Sender secret is not found.
    /// - `Unsupported` Used crypto or method is unsupported.
    /// - `InvalidState` Indicates library error.
    /// - `IOError` IO error during DID or secrets resolving
    ///
    /// TODO: verify and update errors list
    pub async fn pack_signed<T>(
        &self,
        sign_by: &str,
        did_resolver: &DIDCacheClient,
        secrets_resolver: &T,
    ) -> Result<(String, PackSignedMetadata)>
    where
        T: SecretsResolver,
    {
        self._validate_pack_signed(sign_by)?;

        let (did, key_id) = did_or_url(sign_by);

        let did_doc = match did_resolver.resolve(did).await {
            Ok(result) => result.doc,
            Err(e) => {
                return Err(err_msg(
                    ErrorKind::DIDNotResolved,
                    format!("Couldn't resolve ({}). Reason: {}", did, e),
                ));
            }
        };

        let authentications: Vec<String> = if let Some(key_id) = key_id {
            if did_doc.contains_authentication(key_id) {
                vec![key_id.to_string()]
            } else {
                return Err(err_msg(
                    ErrorKind::DIDUrlNotFound,
                    "Signer key id not found in did doc",
                ));
            }
        } else {
            let _did = did_doc.id.as_did();
            did_doc
                .verification_relationships
                .authentication
                .iter()
                .map(|s| s.id().resolve(_did).to_string())
                .collect()
        };

        let key_id = secrets_resolver
            .find_secrets(&authentications)
            .await
            .first()
            .ok_or_else(|| err_msg(ErrorKind::SecretNotFound, "No signer secrets found"))?
            .to_string();

        let secret = secrets_resolver
            .get_secret(&key_id)
            .await
            .ok_or_else(|| err_msg(ErrorKind::SecretNotFound, "Signer secret not found"))?;

        let sign_key = secret.as_key_pair()?;

        let payload = self.pack_plaintext(did_resolver).await?;

        let msg = match sign_key {
            KnownKeyPair::Ed25519(ref key) => {
                jws::sign(payload.as_bytes(), (&key_id, key), Algorithm::EdDSA)
            }
            KnownKeyPair::P256(ref key) => {
                jws::sign(payload.as_bytes(), (&key_id, key), Algorithm::Es256)
            }
            KnownKeyPair::K256(ref key) => {
                jws::sign(payload.as_bytes(), (&key_id, key), Algorithm::Es256K)
            }
            _ => Err(err_msg(ErrorKind::Unsupported, "Unsupported signature alg"))?,
        }?;

        let metadata = PackSignedMetadata {
            sign_by_kid: key_id.to_owned(),
        };

        Ok((msg, metadata))
    }

    fn _validate_pack_signed(&self, sign_by: &str) -> Result<()> {
        if !is_did(sign_by) {
            Err(err_msg(
                ErrorKind::IllegalArgument,
                "`sign_from` value is not a valid DID or DID URL",
            ))?;
        }

        Ok(())
    }
}

/// Additional metadata about this `pack` method execution like used key identifiers.
#[derive(Debug, PartialEq, Eq, Clone, Serialize)]
pub struct PackSignedMetadata {
    /// Identifier (DID URL) of sign key.
    pub sign_by_kid: String,
}

/*
#[cfg(test)]
mod tests {
    use askar_crypto::{
        alg::{ed25519::Ed25519KeyPair, k256::K256KeyPair, p256::P256KeyPair},
        sign::KeySigVerify,
    };
    use base64::prelude::*;
    use serde_json::Value;
    use ssi::did::DIDMethods;

    use crate::{
        did::{
            resolvers::{ExampleDIDResolver, MockDidResolver},
            DIDResolver, VerificationMaterial,
        },
        error::{err_msg, ErrorKind},
        jwk::FromJwkValue,
        jws::{self, Algorithm, Header, ProtectedHeader},
        secrets::{
            resolvers::ExampleSecretsResolver, Secret, SecretMaterial, SecretType, SecretsResolver,
        },
        test_vectors::{
            ALICE_AUTH_METHOD_25519, ALICE_AUTH_METHOD_P256, ALICE_AUTH_METHOD_SECPP256K1,
            ALICE_DID, ALICE_DID_DOC, ALICE_DID_DOC_WITH_NO_SECRETS, ALICE_SECRETS, BOB_DID_DOC,
            BOB_SECRETS, CHARLIE_DID_DOC, CHARLIE_ROTATED_TO_ALICE_SECRETS,
            CHARLIE_SECRET_AUTH_KEY_ED25519, FROM_PRIOR_FULL, MESSAGE_FROM_PRIOR_FULL,
            MESSAGE_SIMPLE, PLAINTEXT_MSG_SIMPLE,
        },
        Message, PackSignedMetadata, UnpackOptions,
    };

    #[tokio::test]
    async fn pack_signed_works() {
        let did_resolver = ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone()]);
        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        _pack_signed_works::<Ed25519KeyPair>(
            &did_resolver,
            &secrets_resolver,
            &MESSAGE_SIMPLE,
            ALICE_DID,
            &ALICE_AUTH_METHOD_25519.id,
            Algorithm::EdDSA,
            PLAINTEXT_MSG_SIMPLE,
            &ALICE_DID_DOC.verification_method[4].verification_material,
        )
        .await;

        _pack_signed_works::<Ed25519KeyPair>(
            &did_resolver,
            &secrets_resolver,
            &MESSAGE_SIMPLE,
            &ALICE_AUTH_METHOD_25519.id,
            &ALICE_AUTH_METHOD_25519.id,
            Algorithm::EdDSA,
            PLAINTEXT_MSG_SIMPLE,
            &ALICE_DID_DOC.verification_method[4].verification_material,
        )
        .await;

        _pack_signed_works::<P256KeyPair>(
            &did_resolver,
            &secrets_resolver,
            &MESSAGE_SIMPLE,
            &ALICE_AUTH_METHOD_P256.id,
            &ALICE_AUTH_METHOD_P256.id,
            Algorithm::Es256,
            PLAINTEXT_MSG_SIMPLE,
            &ALICE_DID_DOC.verification_method[5].verification_material,
        )
        .await;

        _pack_signed_works::<K256KeyPair>(
            &did_resolver,
            &secrets_resolver,
            &MESSAGE_SIMPLE,
            &ALICE_AUTH_METHOD_SECPP256K1.id,
            &ALICE_AUTH_METHOD_SECPP256K1.id,
            Algorithm::Es256K,
            PLAINTEXT_MSG_SIMPLE,
            &ALICE_DID_DOC.verification_method[6].verification_material,
        )
        .await;

        #[allow(clippy::too_many_arguments)]
        async fn _pack_signed_works<'dr, 'sr, Key: KeySigVerify + FromJwkValue>(
            did_resolver: &'dr (dyn DIDResolver + 'dr + Sync),
            secrets_resolver: &'sr (dyn SecretsResolver + 'sr + Sync),
            message: &Message,
            sign_by: &str,
            sign_by_kid: &str,
            alg: Algorithm,
            plaintext: &str,
            verification_material: &VerificationMaterial,
        ) {
            let (msg, metadata) = message
                .pack_signed(sign_by, did_resolver, secrets_resolver)
                .await
                .expect("Unable pack_signed");

            assert_eq!(
                metadata,
                PackSignedMetadata {
                    sign_by_kid: sign_by_kid.into(),
                }
            );

            let msg = jws::parse(&msg).expect("Unable parse");

            assert_eq!(
                msg.protected,
                vec![ProtectedHeader {
                    typ: "application/didcomm-signed+json".into(),
                    alg,
                }]
            );

            let payload: Value = {
                let payload = BASE64_URL_SAFE_NO_PAD
                    .decode(&msg.jws.payload)
                    .expect("Unable decode_config");

                serde_json::from_slice(&payload).expect("Unable from_str")
            };

            let exp_payload: Value = serde_json::from_str(plaintext).expect("Unable from_str");

            assert_eq!(payload, exp_payload);
            assert_eq!(msg.jws.signatures.len(), 1);

            assert_eq!(
                msg.jws.signatures[0].header,
                Header {
                    kid: sign_by_kid.into()
                }
            );

            let signer_key = match verification_material {
                VerificationMaterial::JWK {
                    public_key_jwk: ref value,
                } => Key::from_jwk_value(value).expect("Unable from_jwk_value"),
                _ => panic!("Unexpected verification_material"),
            };

            let valid = msg
                .verify((sign_by_kid, &signer_key))
                .expect("Unable verify");

            assert!(valid);
        }
    }

    #[tokio::test]
    async fn pack_signed_works_signer_did_not_found() {
        let did_resolver = ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone()]);
        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let res = MESSAGE_SIMPLE
            .pack_signed("did:example:unknown", &did_resolver, &secrets_resolver)
            .await;

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::DIDNotResolved);

        assert_eq!(format!("{}", err), "DID not resolved: Signer did not found");
    }

    #[tokio::test]
    async fn pack_signed_works_signer_is_not_did_our_did_url() {
        let mut did_doc = ALICE_DID_DOC.clone();
        did_doc.id = "not-a-did".into();
        let did_resolver = ExampleDIDResolver::new(vec![did_doc]);
        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let res = MESSAGE_SIMPLE
            .pack_signed("not-a-did", &did_resolver, &secrets_resolver)
            .await;

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::IllegalArgument);

        assert_eq!(
            format!("{}", err),
            "Illegal argument: `sign_from` value is not a valid DID or DID URL"
        );
    }

    #[tokio::test]
    async fn pack_signed_works_signer_did_url_not_found() {
        let did_resolver = ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone()]);
        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let res = MESSAGE_SIMPLE
            .pack_signed(
                &format!("{}#unkown", ALICE_DID),
                &did_resolver,
                &secrets_resolver,
            )
            .await;

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::DIDUrlNotFound);

        assert_eq!(
            format!("{}", err),
            "DID URL not found: Signer key id not found in did doc"
        );
    }

    #[tokio::test]
    async fn pack_signed_works_signer_did_resolving_err() {
        let did_resolver =
            MockDidResolver::new(vec![Err(err_msg(ErrorKind::InvalidState, "Mock error"))]);

        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let res = MESSAGE_SIMPLE
            .pack_signed(ALICE_DID, &did_resolver, &secrets_resolver)
            .await;

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::InvalidState);

        assert_eq!(
            format!("{}", err),
            "Invalid state: Unable resolve signer did: Mock error"
        );
    }

    #[tokio::test]
    async fn pack_signed_works_signer_secrets_not_found() {
        let did_resolver = ExampleDIDResolver::new(vec![ALICE_DID_DOC_WITH_NO_SECRETS.clone()]);
        let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

        let res = MESSAGE_SIMPLE
            .pack_signed(
                "did:example:alice#key-not-in-secrets-1",
                &did_resolver,
                &secrets_resolver,
            )
            .await;

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::SecretNotFound);

        assert_eq!(
            format!("{}", err),
            "Secret not found: No signer secrets found"
        );
    }

    #[tokio::test]
    async fn pack_signed_works_unable_instantiate_sign_key() {
        let mut did_doc = ALICE_DID_DOC.clone();
        did_doc
            .authentication
            .push("did:example:alice#key-d25519-1".into());
        let mut secrets = ALICE_SECRETS.clone();
        secrets.push(Secret {
            id: "did:example:alice#key-d25519-1".into(),
            type_: SecretType::JsonWebKey2020,
            secret_material: SecretMaterial::JWK {
                private_key_jwk: serde_json::json!({
                    "kty": "EC",
                    "d": "sB0bYtpaXyp-h17dDpMx91N3Du1AdN4z1FUq02GbmLw",
                    "crv": "A-256",
                    "x": "L0crjMN1g0Ih4sYAJ_nGoHUck2cloltUpUVQDhF2nHE",
                    "y": "SxYgE7CmEJYi7IDhgK5jI4ZiajO8jPRZDldVhqFpYoo",
                }),
            },
        });
        let did_resolver = ExampleDIDResolver::new(vec![did_doc]);
        let secrets_resolver = ExampleSecretsResolver::new(secrets);

        let res = MESSAGE_SIMPLE
            .pack_signed(
                "did:example:alice#key-d25519-1",
                &did_resolver,
                &secrets_resolver,
            )
            .await;

        let err = res.expect_err("res is ok");
        assert_eq!(err.kind(), ErrorKind::Unsupported);

        assert_eq!(
            format!("{}", err),
            "Unsupported crypto or method: Unable instantiate sign key: Unsupported key type or curve"
        );
    }

    #[tokio::test]
    async fn pack_signed_works_from_prior() {
        let mut did_resolver = ExampleDIDResolver::new(vec![
            ALICE_DID_DOC.clone(),
            BOB_DID_DOC.clone(),
            CHARLIE_DID_DOC.clone(),
        ]);
        let charlie_rotated_to_alice_secrets_resolver =
            ExampleSecretsResolver::new(CHARLIE_ROTATED_TO_ALICE_SECRETS.clone());
        let bob_secrets_resolver = ExampleSecretsResolver::new(BOB_SECRETS.clone());

        let (packed_msg, _pack_metadata) = MESSAGE_FROM_PRIOR_FULL
            .pack_signed(
                ALICE_DID,
                &did_resolver,
                &charlie_rotated_to_alice_secrets_resolver,
            )
            .await
            .expect("Unable pack_signed");

        let did_method_resolver = DIDMethods::default();
        let (unpacked_msg, unpack_metadata) = Message::unpack_string(
            &packed_msg,
            &mut did_resolver,
            &did_method_resolver,
            &bob_secrets_resolver,
            &UnpackOptions::default(),
        )
        .await
        .expect("Unable unpack");

        assert_eq!(&unpacked_msg, &*MESSAGE_FROM_PRIOR_FULL);
        assert_eq!(
            unpack_metadata.from_prior_issuer_kid.as_ref(),
            Some(&CHARLIE_SECRET_AUTH_KEY_ED25519.id)
        );
        assert_eq!(unpack_metadata.from_prior.as_ref(), Some(&*FROM_PRIOR_FULL));
    }
}
*/
