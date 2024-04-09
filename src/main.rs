use std::{
    collections::BTreeMap,
    io::{stdout, BufWriter, Write},
};

use axum::{routing::get, Router};
use did_method_key::DIDKey;
use did_peer::{
    DIDPeer, DIDPeerCreateKeys, DIDPeerKeys, DIDPeerService, PeerServiceEndPoint,
    PeerServiceEndPointLong,
};
use serde::Serialize;
use serde_json::map;
use ssi::{
    did::{DIDCreate, DIDMethod, DIDMethods, Document, DocumentBuilder, Source},
    did_resolve::{dereference, DIDResolver, ResolutionInputMetadata},
    jwk::{Params, JWK},
};

/*

did:peer:2.Ez6LSpvZR8uUz1wHHkLSVmbZbsShfxi75N8dLj5mrzLfiHbCC.Vz6MkhNaGZtcjQoVEfTiX7kMQJiwLANsf9eq2KqkRestcJwBt.
           SeyJpZCI6Im5ldy1pZCIsInQiOiJkbSIsInMiOiJodHRwczovL2xvY2FsaG9zdDo3MDM3LyIsInIiOltdLCJhIjpbImRpZGNvbW0vdjIiXX0

*/

#[tokio::main]
async fn main() {
    // test create a did-key
    let mut methods = DIDMethods::default();
    methods.insert(Box::new(DIDKey));
    methods.insert(Box::new(DIDPeer));

    let (res_meta, doc_opt, doc_meta_opt) = methods
        .resolve(
            "did:peer:2.Vz6Mkj3PUd1WjvaDhNZhhhXQdz5UnZXmS7ehtx8bsPpD47kKc.Ez6LSg8zQom395jKLrGiBNruB9MM6V8PWuf2FpEy4uRFiqQBR.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHA6Ly9leGFtcGxlLmNvbS9kaWRjb21tIiwiYSI6WyJkaWRjb21tL3YyIl0sInIiOlsiZGlkOmV4YW1wbGU6MTIzNDU2Nzg5YWJjZGVmZ2hpI2tleS0xIl19fQ.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHA6Ly9leGFtcGxlLmNvbS9hbm90aGVyIiwiYSI6WyJkaWRjb21tL3YyIl0sInIiOlsiZGlkOmV4YW1wbGU6MTIzNDU2Nzg5YWJjZGVmZ2hpI2tleS0yIl19fQ",
            &ResolutionInputMetadata::default(),
        )
        .await;
    println!("res_meta: {:?}", res_meta);
    println!(
        "doc_opt: {}",
        serde_json::to_string_pretty(&doc_opt.unwrap()).unwrap()
    );

    let e_ed25519_key = JWK::generate_ed25519().unwrap();
    let v_ed25519_key = JWK::generate_ed25519().unwrap();

    if let Params::OKP(map) = e_ed25519_key.clone().params {
        println!("E: {} {:?}", map.curve, map.private_key.clone().unwrap());
    }
    if let Params::OKP(map) = v_ed25519_key.clone().params {
        println!("V: {} {:?}", map.curve, map.private_key.clone().unwrap());
    }

    let did = methods.get("key").unwrap();
    let e_key = did.generate(&Source::Key(&e_ed25519_key)).unwrap();
    let v_key = did.generate(&Source::Key(&v_ed25519_key)).unwrap();

    let keys = vec![
        DIDPeerCreateKeys {
            purpose: DIDPeerKeys::Verification,
            public_key_multibase: v_key[8..].to_string(),
        },
        DIDPeerCreateKeys {
            purpose: DIDPeerKeys::Encryption,
            public_key_multibase: e_key[8..].to_string(),
        },
    ];

    let services = vec![DIDPeerService {
        _type: "dm".into(),
        service_end_point: PeerServiceEndPoint::Long(PeerServiceEndPointLong {
            uri: "https://localhost:7037/".into(),
            accept: vec!["didcomm/v2".into()],
            routing_keys: vec![],
        }),
    }];
    let did_peer =
        DIDPeer::create_peer_did(keys, Some(services)).expect("Failed to create did:peer");

    println!("{}", did_peer);

    // build our application with a single route
    let app = Router::new().route("/", get(|| async { "Hello, World!" }));

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
