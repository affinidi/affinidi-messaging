//! Various forwarding examples for the messaging SDK.
//! Requires a working Mediator
//!
//! If you are not seeing log messages, then add the following to your environment
//! `export RUST_LOG=info`

use std::time::SystemTime;

use affinidi_did_resolver_cache_sdk::{config::ClientConfigBuilder, DIDCacheClient};
use affinidi_messaging_didcomm::{secrets::Secret, Message};
use affinidi_messaging_sdk::{
    config::Config, conversions::secret_from_str, errors::ATMError,
    messages::sending::InboundMessageResponse, protocols::Protocols, ATM,
};
use clap::Parser;
use did_peer::{
    DIDPeer, DIDPeerCreateKeys, DIDPeerKeys, DIDPeerService, PeerServiceEndPoint,
    PeerServiceEndPointLong,
};
use serde_json::{json, Map};
use ssi::{
    dids::{document::service::Endpoint, Document, DIDURL},
    json_ld::iref::Uri,
    jwk::Params,
    JWK,
};
use tracing::info;
use tracing_subscriber::filter;
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    ssl_certificates: String,
    #[arg(short, long)]
    mediator_did: String,
}

struct Agent {
    pub did: String,
    pub verification_key: JWK, // Signing key
    pub encryption_key: JWK,
}

impl Agent {
    /// Generate a new agent with a DID, signing key, and encryption key
    /// If a mediator is provided, the agent will have a serviceEndpoint defined
    pub fn new(mediator: Option<&str>) -> Self {
        let mut agent = Agent {
            did: "".to_string(),
            verification_key: JWK::generate_ed25519().unwrap(),
            encryption_key: JWK::generate_secp256k1(),
        };

        let v_did_key = ssi::dids::DIDKey::generate(&agent.verification_key).unwrap();
        let e_did_key = ssi::dids::DIDKey::generate(&agent.encryption_key).unwrap();

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

        let services = mediator.map(|mediator| {
            vec![DIDPeerService {
                _type: "dm".into(),
                service_end_point: PeerServiceEndPoint::Long(PeerServiceEndPointLong {
                    uri: mediator.into(),
                    accept: vec!["didcomm/v2".into()],
                    routing_keys: vec![],
                }),
                id: None,
            }]
        });

        // Create the did:peer DID
        let (did_peer, _) =
            DIDPeer::create_peer_did(&keys, services.as_ref()).expect("Failed to create did:peer");

        agent.did = did_peer;

        agent
    }

    pub fn get_secrets(&self) -> Vec<Secret> {
        let mut secrets: Vec<Secret> = Vec::new();

        let v_key = if let Params::OKP(map) = &self.verification_key.params {
            json!({
                "crv": map.curve,
                "d": map.private_key.clone().unwrap(),
                "kty": "OKP",
                "x": map.public_key.clone()
            })
        } else {
            panic!("Verification key is not an OKP key");
        };

        secrets.push(secret_from_str(&format!("{}#key-1", self.did), &v_key));

        let e_key = if let Params::EC(map) = &self.encryption_key.params {
            json!({
                "crv": map.curve.clone().unwrap(),
                "d": map.ecc_private_key.clone().unwrap(),
                "kty": "EC",
                "x": map.x_coordinate.clone().unwrap(),
                "y": map.y_coordinate.clone().unwrap(),
            })
        } else {
            panic!("Encryption key is not an EC key");
        };
        secrets.push(secret_from_str(&format!("{}#key-2", self.did), &e_key));

        secrets
    }
}

fn get_mediator_service_endpoint(mediator: &Document) -> Option<String> {
    mediator.service.iter().find_map(|service| {
        service.service_endpoint.as_ref().and_then(|endpoint| {
            endpoint.first().and_then(|endpoint| match endpoint {
                Endpoint::Uri(uri) => Some(uri.to_string()),
                Endpoint::Map(map) => map
                    .get("uri")
                    .and_then(|uri| uri.as_str())
                    .map(|uri| uri.to_string()),
            })
        })
    })
}

#[tokio::main]
async fn main() -> Result<(), ATMError> {
    // **************************************************************
    // *** Initial setup
    // **************************************************************

    let args = Args::parse();
    // construct a subscriber that prints formatted traces to stdout
    let subscriber = tracing_subscriber::fmt()
        // Use a more compact, abbreviated log format
        .with_env_filter(filter::EnvFilter::from_default_env())
        .finish();
    // use that subscriber to process traces emitted after this point
    tracing::subscriber::set_global_default(subscriber).expect("Logging failed, exiting...");

    // ATM SDK supports an externally created DID Cache Resolver
    let did_resolver = DIDCacheClient::new(ClientConfigBuilder::default().build())
        .await
        .expect("Couldn't create DID Resolver!");

    // **************************************************************
    // *** Alice DID and keys setup
    // **************************************************************

    let alice = Agent::new(None);
    let alice_secrets = alice.get_secrets();

    info!("Alice: {}", alice.did);

    // **************************************************************
    // *** Bob DID and keys setup
    // *** Bob is using the mediator as a service endpoint that
    // *** will be used for routing messages
    // **************************************************************

    let bob = Agent::new(Some(&args.mediator_did));
    let bob_secrets = bob.get_secrets();

    info!("Bob: {}", bob.did);

    // **************************************************************
    // *** Create ATM SDK instances for Alice and Bob
    // *** Each SDK instance has the respective DID and Keys for each agent
    // **************************************************************

    // Derive network address from the Mediator DID
    let mediator = did_resolver
        .resolve(&args.mediator_did)
        .await
        .expect("Couldn't resolve mediator DID");

    let mediator_address = get_mediator_service_endpoint(&mediator.doc)
        .expect("Couldn't find mediator service endpoint URI in DID Document");

    info!("Mediator Address: {}", mediator_address);

    // **************************************************************
    // *** Alice ATM SDK setup
    // **************************************************************

    let alice_config = Config::builder()
        .with_my_did(&alice.did)
        .with_atm_did(&args.mediator_did)
        .with_external_did_resolver(&did_resolver)
        .with_atm_api(&mediator_address)
        .with_secret(alice_secrets[0].clone())
        .with_secret(alice_secrets[1].clone())
        .with_ssl_certificates(&mut vec![args.ssl_certificates.clone()]);

    let mut atm_alice = ATM::new(alice_config.build()?).await?;

    // **************************************************************
    // *** Bob ATM SDK setup
    // **************************************************************
    let bob_config = Config::builder()
        .with_my_did(&bob.did)
        .with_atm_did(&args.mediator_did)
        .with_external_did_resolver(&did_resolver)
        .with_atm_api(&mediator_address)
        .with_secret(bob_secrets[0].clone())
        .with_secret(bob_secrets[1].clone())
        .with_ssl_certificates(&mut vec![args.ssl_certificates]);

    let mut atm_bob = ATM::new(bob_config.build()?).await?;

    // Protocols can be shared between ALice and Bob ATM SDK instances
    let protocols = Protocols::new();

    // Alice is creating her message to Bob
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let msg = Message::build(
        Uuid::new_v4().into(),
        "example/v1".to_owned(),
        json!("Hello Bob! Message sent via DIDComm from Alice"),
    )
    .to(bob.did.clone())
    .from(alice.did.clone())
    .created_time(now)
    .expires_time(now + 300)
    .finalize();

    // Pack the message
    let (msg, _) = atm_alice
        .pack_encrypted(&msg, &bob.did, Some(&alice.did), Some(&alice.did))
        .await
        .map_err(|e| ATMError::MsgSendError(format!("Error packing message: {}", e)))?;

    let response = atm_alice
        .send_didcomm_message::<InboundMessageResponse>(&msg, true)
        .await?;

    println!("Sent message response: {:?}", response);

    Ok(())
}
