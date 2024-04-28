use did_peer::DIDPeer;
use didcomm::{
    protocols::routing::try_parse_forward,
    secrets::{Secret, SecretMaterial, SecretType},
    Message, PackEncryptedOptions, UnpackOptions,
};
use didcomm_mediator::{
    common::did_conversion::convert_did,
    resolvers::{affinidi_dids::AffinidiDIDResolver, affinidi_secrets::AffinidiSecrets},
};
use serde_json::json;
use ssi::{
    did::DIDMethods,
    did_resolve::{DIDResolver, ResolutionInputMetadata},
};

const MEDIATOR_DID: &str = "did:peer:2.Vz6Mkp9f4p6rSJkgbxTpPXL861PSN6EB996fQv5vCq5Q9C5Me.EzQ3shpFNDUgbePPhbLmwNcTiNSAhcb511urztSmT7aavVamJ3.SeyJ0IjoiRElEQ29tbU1lc3NhZ2luZyIsInMiOnsidXJpIjoiaHR0cHM6Ly8xMjcuMC4wLjE6NzAzNyIsImEiOlsiZGlkY29tbS92MiJdLCJyIjpbXX19";
const ALICE_DID: &str = "did:peer:2.Vz6MkpwZQVX9QJz52XPEgC2Bcnfw85M7gALURiQtsXE4p3DTs.EzQ3shdKMPYJafjhf1Zf3fVcskZ7Zua2W5SNbXgv2LjVQTehCF.SeyJ0IjoiRElEQ29tbU1lc3NhZ2luZyIsInMiOnsidXJpIjoiaHR0cHM6Ly8xMjcuMC4wLjE6NzAzNyIsImEiOlsiZGlkY29tbS92MiJdLCJyIjpbXX19";
const BOB_DID: &str =   "did:peer:2.Vz6MkojGQfxoRkNsFXjstcd2hwxvv1rnfTqu2K3broED94UZ8.EzQ3shTr4Cqcz3RcMztJ3M4NRAAeoDA5Q4eQ5wEPtuZk4sg2MZ.SeyJ0IjoiRElEQ29tbU1lc3NhZ2luZyIsInMiOnsidXJpIjoiaHR0cHM6Ly8xMjcuMC4wLjE6NzAzNyIsImEiOlsiZGlkY29tbS92MiJdLCJyIjpbImRpZDpwZWVyOjIuVno2TWtwOWY0cDZyU0prZ2J4VHBQWEw4NjFQU042RUI5OTZmUXY1dkNxNVE5QzVNZS5FelEzc2hwRk5EVWdiZVBQaGJMbXdOY1RpTlNBaGNiNTExdXJ6dFNtVDdhYXZWYW1KMy5TZXlKMElqb2lSRWxFUTI5dGJVMWxjM05oWjJsdVp5SXNJbk1pT25zaWRYSnBJam9pYUhSMGNITTZMeTh4TWpjdU1DNHdMakU2TnpBek55SXNJbUVpT2xzaVpHbGtZMjl0YlM5Mk1pSmRMQ0p5SWpwYlhYMTkja2V5LTIiXX19";

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
              "d": "2_74tkY50_DFpLAHnKd9TUncl84S0NWZBqOQf2Yb2NU",
              "kty": "OKP",
              "x": "kBJx18jGP3bW_7vkmvSUiYzbFLwch0VBI-XRVowAONU"
            }),
        },
    };

    let mediator_e_secret = Secret {
        id: [MEDIATOR_DID.to_string(), "#key-2".to_string()].concat(),
        type_: SecretType::JsonWebKey2020,
        secret_material: SecretMaterial::JWK {
            private_key_jwk: json!({
              "crv": "secp256k1",
              "d": "CAxZcOofg3sSnQ6Pg4Ee22xEC1ykRfbNy1DEKRb68Lo",
              "kty": "EC",
              "x": "jsGSSTNv153VzdENREUACvlyLxh5UGPeE39UDXGyx9Q",
              "y": "JGD1od91aLLz478tGgvR2LUs8cMK9FKzBa6bL5fX1bE"
            }),
        },
    };

    let alice_e_secret: Secret = Secret {
        id: [ALICE_DID.to_string(), "#key-2".to_string()].concat(),
        type_: SecretType::JsonWebKey2020,
        secret_material: SecretMaterial::JWK {
            private_key_jwk: json!({
              "crv": "secp256k1",
              "d": "4tMWf9hAOR_S_pSuQ6HqO5M4PojTFEhbKB1dafvilvM",
              "kty": "EC",
              "x": "7FZnaHwOSUuvFkPRXPnJiUdV9vP_grt2BJZwfkZBHfQ",
              "y": "xL2gNgb4EfSJJ6uB6eYV-O6xyio0hPeYum04HADBqsY"
            }),
        },
    };

    let alice_v_secret: Secret = Secret {
        id: [ALICE_DID.to_string(), "#key-1".to_string()].concat(),
        type_: SecretType::JsonWebKey2020,
        secret_material: SecretMaterial::JWK {
            private_key_jwk: json!({
              "crv": "Ed25519",
              "d": "y413N3_Gp6XwMvh-VtLLx97h7Cm9ygk_2YQc3GfqNxw",
              "kty": "OKP",
              "x": "m9TC56MDvFBzGaB5OUmK3pjFCohyu8sKP9e12MDebyY"
            }),
        },
    };

    let bob_e_secret: Secret = Secret {
        id: [BOB_DID.to_string(), "#key-2".to_string()].concat(),
        type_: SecretType::JsonWebKey2020,
        secret_material: SecretMaterial::JWK {
            private_key_jwk: json!({
              "crv": "secp256k1",
              "d": "Q3jovxzI8llisHswkuwpzMSEU84uI2i0wtokr-2dxZc",
              "kty": "EC",
              "x": "X58b8qkteYxvRBRlTEJd4F3GQoQHQj_eNswdm4xImqQ",
              "y": "TkQOZJskdJyAe5g3-ELU_knaMtwgd8UGD9Ek95g__PI"
            }),
        },
    };

    let bob_v_secret: Secret = Secret {
        id: [BOB_DID.to_string(), "#key-1".to_string()].concat(),
        type_: SecretType::JsonWebKey2020,
        secret_material: SecretMaterial::JWK {
            private_key_jwk: json!({
              "crv": "Ed25519",
              "d": "3psa0xsEv0Otdz6vr8HjokWoiZyAU04xhjYwBdn2daI",
              "kty": "OKP",
              "x": "idLi4fT5nqf2J_eytLOuxObMaINXmDuf1StBoRJKhcs"
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
    let bob_did_doc = convert_did(&bob_doc_opt.unwrap()).unwrap();

    /*let a = bob_doc_opt.unwrap();
    let bob_did_doc = convert_did(&a).unwrap();
    let b = bob_did_doc
        .service
        .clone()
        .first()
        .unwrap()
        .service_endpoint
        .clone();*/

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
