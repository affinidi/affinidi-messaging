use axum::{routing::get, Router};
use did_peer::DIDPeer;
use didcomm::{
    protocols::routing::try_parse_forward,
    secrets::{
        resolvers::ExampleSecretsResolver, Secret, SecretMaterial, SecretType, SecretsResolver,
    },
    Message, PackEncryptedOptions, UnpackOptions,
};
use didcomm_mediator::{
    common::did_conversion::convert_did,
    resolvers::{affinidi_dids::AffinidiDIDResolver, affinidi_secrets::AffinidiSecrets},
};
use serde_json::{json, Value};
use ssi::{
    did::{DIDMethods, ServiceEndpoint},
    did_resolve::{DIDResolver, ResolutionInputMetadata},
};

const MEDIATOR_DID: &str = "did:peer:2.Vz6Mkv5pcmEszkp4tLfAvHfMxME7GTwVspuETDon9C2LXyS49.EzDnaepcvcQifEuGktjFazZ1FMTzELf6hWWcWoFaQdTJrR89Lz.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHBzOi8vbG9jYWxob3N0OjcwMzcvIiwiYWNjZXB0IjpbImRpZGNvbW0vdjIiXSwicm91dGluZ19rZXlzIjpbXX19";
const ALICE_DID: &str = "did:peer:2.Vz6MknrybrXop8wjecgH5gNZ4bajiztB1EuJ1aPJW1PsLaFcP.EzDnaeYzK9dTHipxp7QxvUADomBdLsSSvPsHBMc93g4BvSviHZ.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHBzOi8vbG9jYWxob3N0OjcwMzcvIiwiYWNjZXB0IjpbImRpZGNvbW0vdjIiXSwicm91dGluZ19rZXlzIjpbXX19";
const BOB_DID: &str =   "did:peer:2.Vz6MkfRViUo3fADYPnpQeyJLCgtGsMfwqSUcEq7Jx6VrbA2Yg.EzDnaezTcKcJKooedjzf1tzFZs1eqVJwipRWDjDHJ7svXDpm6C.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHBzOi8vbG9jYWxob3N0OjcwMzcvIiwiYWNjZXB0IjpbImRpZGNvbW0vdjIiLCJkaWRjb21tL2FpcDI7ZW52PXJmYzU4NyJdLCJyb3V0aW5nX2tleXMiOlsiZGlkOnBlZXI6Mi5WejZNa3Y1cGNtRXN6a3A0dExmQXZIZk14TUU3R1R3VnNwdUVURG9uOUMyTFh5UzQ5LkV6RG5hZXBjdmNRaWZFdUdrdGpGYXpaMUZNVHpFTGY2aFdXY1dvRmFRZFRKclI4OUx6LlNleUowSWpvaVpHMGlMQ0p6SWpwN0luVnlhU0k2SW1oMGRIQnpPaTh2Ykc5allXeG9iM04wT2pjd016Y3ZJaXdpWVdOalpYQjBJanBiSW1ScFpHTnZiVzB2ZGpJaVhTd2ljbTkxZEdsdVoxOXJaWGx6SWpwYlhYMTkja2V5LTIiXX19";

#[tokio::main]
async fn main() {
    let mut did_resolver = DIDMethods::default();
    did_resolver.insert(Box::new(DIDPeer));

    let mediator_v_secret: Secret = Secret {
        id: [MEDIATOR_DID.to_string(), "#key-1".to_string()].concat(),
        type_: SecretType::JsonWebKey2020,
        secret_material: SecretMaterial::JWK {
            private_key_jwk: json!({
              "crv": "Ed25519",
              "d": "QxPh4AUPAovUvgHoFruF1hobtttkx5OdIqKMlI4VqRE",
              "kty": "OKP",
              "x": "6D0Kz3AC_CVQpIpfLr8gXV2odJHbBIk5U_KOH5Dj0Ho"
            }),
        },
    };

    let mediator_e_secret = Secret {
        id: [MEDIATOR_DID.to_string(), "#key-2".to_string()].concat(),
        type_: SecretType::JsonWebKey2020,
        secret_material: SecretMaterial::JWK {
            private_key_jwk: json!({
              "crv": "P-256",
              "d": "73qOI4G6BBuCUBEX0hxDf1pr5XM-woxhgRWNytDziS8",
              "kty": "EC",
              "x": "Z2cfPLPCSzr9YcsghwBMh0gzXKutfDkMayU8mHkCyx8",
              "y": "H0pLvsJUoxDfmonOXPA_7IoaAcvBadDFVCMlmenVyvc"
            }),
        },
    };

    let alice_e_secret: Secret = Secret {
        id: [ALICE_DID.to_string(), "#key-2".to_string()].concat(),
        type_: SecretType::JsonWebKey2020,
        secret_material: SecretMaterial::JWK {
            private_key_jwk: json!({
              "crv": "P-256",
              "d": "XWySi0rzVLJaAOWV50osao0GcO7pz1sdEBsBKA_RGQU",
              "kty": "EC",
              "x": "fybP8kGHSVHRgitU5yJ9PSi72ghoLrOupSYUsv7X-nw",
              "y": "YaeVN4fJZhvhsMgjMVideamGtzVVCdVfCiNLkXM_Rfg"
            }),
        },
    };

    let alice_v_secret: Secret = Secret {
        id: [ALICE_DID.to_string(), "#key-1".to_string()].concat(),
        type_: SecretType::JsonWebKey2020,
        secret_material: SecretMaterial::JWK {
            private_key_jwk: json!({
              "crv": "Ed25519",
              "d": "ZSpssmdTSLpvHo_iGsJAXQtmDihdNByTga9F6F9Kflo",
              "kty": "OKP",
              "x": "fPDXgu2GDKop7IpZ9LJxVRT28W85jIcK8GZ4AbpNURQ"
            }),
        },
    };

    let bob_e_secret: Secret = Secret {
        id: [BOB_DID.to_string(), "#key-2".to_string()].concat(),
        type_: SecretType::JsonWebKey2020,
        secret_material: SecretMaterial::JWK {
            private_key_jwk: json!({
              "crv": "P-256",
              "d": "30Ad-i5MyIP7KGmjmZlQXAgV3wnkJWJgEfAOfMt_idw",
              "kty": "EC",
              "x": "-ZkVdPr8kXRHHqfdbk9grilzwqjBvLXNw2nLVVWILnU",
              "y": "smQktql5yFapdtoH2j5AJ8A6brOJEt_5NFqSe2Vmwv0"
            }),
        },
    };

    let bob_v_secret: Secret = Secret {
        id: [BOB_DID.to_string(), "#key-1".to_string()].concat(),
        type_: SecretType::JsonWebKey2020,
        secret_material: SecretMaterial::JWK {
            private_key_jwk: json!({
              "crv": "Ed25519",
              "d": "YynH_yKkmteZhFqFeasHH54vd84LFUn2mQNr7l1hxIQ",
              "kty": "OKP",
              "x": "Dmf7itWx59fyEaNFFn2OO5LpH6G_zwFl_gCZheFAm_k"
            }),
        },
    };
    /* ******************************************************************************************************************************************** */
    /* ******************************************************************************************************************************************** */
    /* ******************************************************************************************************************************************** */
    let (_, mediator_doc_opt, _) = did_resolver
        .resolve(MEDIATOR_DID, &ResolutionInputMetadata::default())
        .await;
    let mediator_doc_opt = DIDPeer::expand_keys(&mediator_doc_opt.unwrap()).await;

    let (_, alice_doc_opt, _) = did_resolver
        .resolve(ALICE_DID, &ResolutionInputMetadata::default())
        .await;
    let alice_doc_opt = DIDPeer::expand_keys(&alice_doc_opt.unwrap()).await;

    let (_, bob_doc_opt, _) = did_resolver
        .resolve(BOB_DID, &ResolutionInputMetadata::default())
        .await;
    let bob_doc_opt = DIDPeer::expand_keys(&bob_doc_opt.unwrap()).await;

    let mediator_did_doc = convert_did(&mediator_doc_opt.unwrap()).unwrap();

    let alice_did_doc = convert_did(&alice_doc_opt.unwrap()).unwrap();
    //let bob_did_doc = convert_did(&bob_doc_opt.unwrap()).unwrap();

    let a = bob_doc_opt.unwrap();
    let bob_did_doc = convert_did(&a).unwrap();
    let b = bob_did_doc
        .service
        .clone()
        .first()
        .unwrap()
        .service_endpoint
        .clone();

    //println!("ServiceEndpoint::Map(map) = \n{:?}\n", b);

    let did_resolver = AffinidiDIDResolver::new(vec![
        mediator_did_doc.clone(),
        alice_did_doc.clone(),
        bob_did_doc.clone(),
    ]);

    // ********************************************************************************************************
    // ********************************************************************************************************

    // repudiable_authenticated_encryption() {
    // --- Building message from ALICE to BOB ---
    let msg = Message::build(
        "test-id-1".to_owned(),
        "affinidi-ASM/v1".to_owned(),
        json!("C# is lame..."),
    )
    .to(BOB_DID.to_owned())
    .from(ALICE_DID.to_owned())
    .finalize();

    println!("Raw message from Alice is\n{:?}\n", msg);

    // --- Packing encrypted and authenticated message ---

    let secrets_resolver =
        AffinidiSecrets::new(vec![alice_v_secret.clone(), alice_e_secret.clone()]);

    let (msg, metadata) = msg
        .pack_encrypted(
            BOB_DID,
            Some(ALICE_DID),
            None,
            &did_resolver,
            &secrets_resolver,
            &PackEncryptedOptions::default(),
        )
        .await
        .expect("Unable pack_encrypted");

    println!("Encryption metadata is\n{:?}\n", metadata);

    // --- Sending message by Alice ---
    println!("Alice is sending message \n{}\n", msg);

    // --- Unpacking message by Mediator1 ---

    let secrets_resolver =
        AffinidiSecrets::new(vec![mediator_e_secret.clone(), mediator_v_secret.clone()]);

    let (msg, metadata) = Message::unpack(
        &msg,
        &did_resolver,
        &secrets_resolver,
        &UnpackOptions::default(),
    )
    .await
    .expect("Unable unpack");

    println!("Mediator1 received message is \n{:?}\n", msg);

    println!(
        "Mediator1 received message unpack metadata is \n{:?}\n",
        metadata
    );

    // --- Forwarding message by Mediator1 ---
    let msg = serde_json::to_string(&try_parse_forward(&msg).unwrap().forwarded_msg).unwrap();

    println!("Mediator1 is forwarding message \n{}\n", msg);

    // --- Unpacking message by Bob ---

    let secrets_resolver = AffinidiSecrets::new(vec![bob_e_secret.clone(), bob_v_secret.clone()]);

    let (msg, metadata) = Message::unpack(
        &msg,
        &did_resolver,
        &secrets_resolver,
        &UnpackOptions::default(),
    )
    .await
    .expect("Unable unpack");

    println!("Bob received message is \n{:?}\n", msg);
    println!("Bob received message unpack metadata is \n{:?}\n", metadata);

    /*
    let secrets_resolver = AffinidiSecrets::new(vec![alice_v_secret, alice_e_secret]);

    let (_, mediator_doc_opt, _) = did_resolver
        .resolve(MEDIATOR_DID, &ResolutionInputMetadata::default())
        .await;
    let mediator_doc_opt = DIDPeer::expand_keys(&mediator_doc_opt.unwrap()).await;

    let (_, alice_doc_opt, _) = did_resolver
        .resolve(ALICE_DID, &ResolutionInputMetadata::default())
        .await;
    let alice_doc_opt = DIDPeer::expand_keys(&alice_doc_opt.unwrap()).await;

    let (_, bob_doc_opt, _) = did_resolver
        .resolve(BOB_DID, &ResolutionInputMetadata::default())
        .await;
    let bob_doc_opt = DIDPeer::expand_keys(&bob_doc_opt.unwrap()).await;

    let mediator_did_doc = convert_did(&mediator_doc_opt.unwrap()).unwrap();
    println!(
        "Alice DIDDoc = \n{}\n",
        serde_json::to_string_pretty(&alice_doc_opt.as_ref().unwrap()).unwrap()
    );
    let alice_did_doc = convert_did(&alice_doc_opt.unwrap()).unwrap();
    let bob_did_doc = convert_did(&bob_doc_opt.unwrap()).unwrap();

    let dids_resolver = AffinidiDIDResolver::new(vec![
        mediator_did_doc.clone(),
        alice_did_doc.clone(),
        bob_did_doc.clone(),
    ]);

    let msg = Message::build("test-id".into(), "test/v1".into(), json!("example-body"))
        .to(BOB_DID.into())
        .from(ALICE_DID.into())
        .finalize();

    println!("Message: {}", serde_json::to_string_pretty(&msg).unwrap());

    let (msg, metadata) = msg
        .pack_encrypted(
            BOB_DID,
            Some(ALICE_DID),
            Some(ALICE_DID),
            &dids_resolver,
            &secrets_resolver,
            &PackEncryptedOptions::default(),
        )
        .await
        .expect("Unable pack_encrypted");

    println!("Encryption metadata is\n{:?}\n", metadata);

    // --- Sending message by Alice ---
    println!("Alice is sending message \n{}\n", msg);

    /*
    println!(
        "Alice DIDDoc = \n{}\n",
        serde_json::to_string_pretty(&alice_did_doc).unwrap()
    );
    println!();

    println!(
        "Mediator DIDDoc = \n{}\n",
        serde_json::to_string_pretty(&mediator_did_doc).unwrap()
    );
    println!();
    */

    let secrets_resolver = AffinidiSecrets::new(vec![mediator_v_secret, mediator_e_secret]);

    let (msg, metadata) = Message::unpack(
        &msg,
        &dids_resolver,
        &secrets_resolver,
        &UnpackOptions::default(),
    )
    .await
    .expect("Unable unpack");

    println!("Mediator1 received message is \n{:?}\n", msg);

    println!(
        "Mediator1 received message unpack metadata is \n{:?}\n",
        metadata
    );

    // --- Forwarding message by Mediator1 ---
    let msg = serde_json::to_string(&try_parse_forward(&msg).unwrap().forwarded_msg).unwrap();

    println!("Mediator1 is forwarding message \n{}\n", msg);

    let (msg, metadata) = Message::unpack(
        &msg,
        &dids_resolver,
        &secrets_resolver,
        &UnpackOptions::default(),
    )
    .await
    .expect("Unable unpack");

    println!("Bob received message is \n{:?}\n", msg);
    println!("Bob received message unpack metadata is \n{:?}\n", metadata);

    // build our application with a single route
    let app = Router::new().route("/", get(|| async { "Hello, World!" }));

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
    */
}
