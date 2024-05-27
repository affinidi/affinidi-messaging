use did_peer::DIDPeer;
use didcomm::{
    secrets::{Secret, SecretMaterial, SecretType},
    Message, PackEncryptedOptions,
};
use didcomm_mediator::{
    common::{did_conversion::convert_did, errors::SuccessResponse},
    handlers::message_inbound::ResponseData,
    resolvers::{affinidi_dids::AffinidiDIDResolver, affinidi_secrets::AffinidiSecrets},
};
use reqwest::{Certificate, Client};
use serde_json::json;
use ssi::{did::DIDMethod, did_resolve::ResolutionInputMetadata};
use std::{
    fs,
    io::{self, Read},
    time::SystemTime,
};
use uuid::Uuid;

static MY_DID: &str = "did:peer:2.Vz6MkgWJfVmPELozq6aCycK3CpxHN8Upphn3WSuQkWY6iqsjF.EzQ3shfb7vwQaTJqFkt8nRfo7Nu98tmeYpdDfWgrqQitDaqXRz";
static MEDIATOR_DID: &str = "did:peer:2.Vz6MkiXGPX2fvUinqRETvsbS2PDjwSksnoU9X94eFwUjRbbZJ.EzQ3shXbp9EFX7JzH2rPVfEfAEAYA4ifv4qY5sLcRgZxLHY42W.SeyJ0IjoiRElEQ29tbU1lc3NhZ2luZyIsInMiOnsidXJpIjoiaHR0cHM6Ly8xMjcuMC4wLjE6NzAzNyIsImEiOlsiZGlkY29tbS92MiJdLCJyIjpbXX19";

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Load DID's
    let did_resolver = load_dids().await;

    let v1_secret = Secret {
        id: [MY_DID.to_string(), "#key-1".to_string()].concat(),
        type_: SecretType::JsonWebKey2020,
        secret_material: SecretMaterial::JWK {
            private_key_jwk: json!({
              "crv": "Ed25519",
              "d": "LLWCf83n8VsUYq31zlZRe0NNMCcn1N4Dh85dGpIqSFw",
              "kty": "OKP",
              "x": "Hn8T4ZjjT0oJ6rjhqox8AykwC3GDFsJF6KkaYZExwQo"
            }),
        },
    };

    let e1_secret = Secret {
        id: [MY_DID.to_string(), "#key-2".to_string()].concat(),
        type_: SecretType::JsonWebKey2020,
        secret_material: SecretMaterial::JWK {
            private_key_jwk: json!({
              "crv": "secp256k1",
              "d": "oi-dXG4EqfNODFPjv2vkieoLdbQZH9k6dwPDV8HDoms",
              "kty": "EC",
              "x": "DhfaXbhwo0KkOiyA5V1K1RZx6Ikr86h_lX5GOwxjmjE",
              "y": "PpYqybOwMsm64vftt-7gBCQPIUbglMmyy_6rloSSAPk"
            }),
        },
    };
    // Load Secret's
    let secrets_resolver = AffinidiSecrets::new(vec![v1_secret, e1_secret]);

    // Set a process wide default crypto provider.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let client = init_client()?;

    // Build the ping message
    let msg = create_ping(MEDIATOR_DID, true);

    println!("Ping message is\n{:#?}\n", msg);

    let (msg, metadata) = msg
        .pack_encrypted(
            MEDIATOR_DID,
            Some(MY_DID),
            Some(MY_DID),
            &did_resolver,
            &secrets_resolver,
            &PackEncryptedOptions::default(),
        )
        .await
        .expect("Unable pack_encrypted");

    println!("Encryption metadata is\n{:?}\n", metadata);

    // --- Sending message by Alice ---
    println!("Alice is sending message \n{}\n", msg);

    let res = client
        .post("https://localhost:7037/atm/v1/inbound")
        .header("Content-Type", "application/json")
        .body(msg)
        .send()
        .await
        .map_err(|e| error(format!("Could not get: {:?}", e)))?;
    println!("Status:\n{}", res.status());
    //println!("Headers:\n{:#?}", res.headers());

    let body = res.text().await.unwrap();

    println!();
    let results = serde_json::from_str::<SuccessResponse<ResponseData>>(&body)
        .ok()
        .unwrap();
    let msg = results.data.clone().unwrap().body;

    println!(
        "Received metadata is\n{:#?}\n",
        &results.data.unwrap().metadata
    );
    println!();
    println!("Received message is\n{:#?}\n", msg);

    /*
    let mut did_method_resolver = DIDMethods::default();
    did_method_resolver.insert(Box::new(DIDPeer));

    let a = Message::unpack_string(
        &msg,
        &mut did_resolver,
        &did_method_resolver,
        &secrets_resolver,
        &UnpackOptions::default(),
    )
    .await;

    println!("Unpacked message is\n{:#?}\n", a.unwrap().0);*/

    Ok(())
}

async fn load_dids() -> AffinidiDIDResolver {
    let peer_method = DIDPeer;
    let (_, d1, _) = peer_method
        .to_resolver()
        .resolve(MY_DID, &ResolutionInputMetadata::default())
        .await;
    let d1 = DIDPeer::expand_keys(&d1.unwrap()).await;
    let d1 = convert_did(&d1.unwrap()).unwrap();

    let (_, d2, _) = peer_method
        .to_resolver()
        .resolve(MEDIATOR_DID, &ResolutionInputMetadata::default())
        .await;
    let d2 = DIDPeer::expand_keys(&d2.unwrap()).await;
    let d2 = convert_did(&d2.unwrap()).unwrap();

    AffinidiDIDResolver::new(vec![d1, d2])
}

/// Creates a DIDComm trust ping message
/// # Arguments
/// * `to_did` - The DID of the recipient
/// * `response` - Whether a response is requested
/// # Returns
/// A DIDComm message to be sent
///
/// Notes:
/// - This message will expire after 5 minutes
fn create_ping(to_did: &str, response: bool) -> Message {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    Message::build(
        Uuid::new_v4().into(),
        "https://didcomm.org/trust-ping/2.0/ping".to_owned(),
        json!(format!("response_requested: {}", response)),
    )
    .to(to_did.to_owned())
    .from(MY_DID.to_owned())
    .created_time(now)
    .expires_time(now + 300)
    .finalize()
}

fn init_client() -> Result<Client, std::io::Error> {
    let certs = load_certs("conf/keys/client.chain")?;

    let mut client = reqwest::ClientBuilder::new()
        .use_rustls_tls()
        .https_only(true)
        .user_agent("Affinidi Trusted Messaging");

    for cert in certs {
        client = client.add_root_certificate(cert);
    }

    let client = client.build().unwrap();

    // Build the hyper client from the HTTPS connector
    Ok(client)
}

fn load_certs(path: &str) -> io::Result<Vec<Certificate>> {
    let mut f =
        fs::File::open(path).map_err(|e| error(format!("failed to open {}: {}", path, e)))?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;

    reqwest::Certificate::from_pem_bundle(&buf)
        .map_err(|e| error(format!("failed to read {}: {}", path, e)))
}

fn error(err: String) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err)
}
