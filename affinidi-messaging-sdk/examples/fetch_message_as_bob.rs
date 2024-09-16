use affinidi_messaging_sdk::{
    config::Config,
    conversions::secret_from_str,
    messages::{fetch::FetchOptions, FetchDeletePolicy},
    ATM,
};
use clap::Parser;
use serde_json::json;
use std::error::Error;
use tracing::info;
use tracing_subscriber::filter;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    network_address: String,
    #[arg(short, long)]
    ssl_certificates: String,
    #[arg(short, long)]
    mediator_did: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
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

    info!("Running with address: {}", &args.network_address);
    info!("Running with mediator_did: {}", &args.mediator_did);
    info!("Running with ssl_certificates: {}", &args.ssl_certificates);

    // DIDs of sender(your DID) and recipient
    let recipient_did = "did:peer:2.Vz6Mkihn2R3M8nY62EFJ7MAVXu7YxsTnuS5iAhmn3qKJbkdFf.EzQ3shpZRBUtewwzYiueXgDqs1bvGNkSyGoRgsbZJXt3TTb9jD.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHBzOi8vbG9jYWxob3N0OjcwMzcvIiwiYWNjZXB0IjpbImRpZGNvbW0vdjIiXSwicm91dGluZ19rZXlzIjpbXX0sImlkIjpudWxsfQ";

    // DID of the Mediator
    let mediator_did = &args.mediator_did;

    // Signing and verification key
    let verification_key1 = json!({
      "crv": "Ed25519",
      "d": "FZMJijqdcp7PCQShgtFj6Ud3vjZY7jFZBVvahziaMMM",
      "kty": "OKP",
      "x": "PybG95kyeSfGRebp4T7hzA7JQuysc6mZ97nM2ety6Vo"
    });

    // Encryption key
    let encryption_key1 = json!({
      "crv": "secp256k1",
      "d": "ai7B5fgT3pCBHec0I4Y1xXpSyrEHlTy0hivSlddWHZE",
      "kty": "EC",
      "x": "k2FhEi8WMxr4Ztr4u2xjKzDESqVnGg_WKrN1820wPeA",
      "y": "fq0DnZ_duPWyeFK0k93bAzjNJVVHEjHFRlGOJXKDS18"
    });

    let mut config = Config::builder()
        .with_my_did(recipient_did)
        .with_atm_did(mediator_did)
        .with_websocket_disabled();

    config = config
        .with_atm_api(&args.network_address)
        .with_ssl_certificates(&mut vec![args.ssl_certificates.into()]);

    // Create a new ATM Client
    let mut atm = ATM::new(config.build()?).await?;
    // Add sender's secrets to ATM Client - these keys stays local.
    atm.add_secret(secret_from_str(
        &format!("{}#key-1", recipient_did),
        &verification_key1,
    ));
    atm.add_secret(secret_from_str(
        &format!("{}#key-2", recipient_did),
        &encryption_key1,
    ));

    // Get the messages from ATM
    let msgs = atm
        .fetch_messages(&FetchOptions {
            limit: 10,
            start_id: None,
            delete_policy: FetchDeletePolicy::OnReceive,
        })
        .await?;

    for msg in msgs.success {
        let (received_msg_unpacked, _) = atm.unpack(&msg.msg.unwrap()).await?;
        info!("Message received: {:?}", received_msg_unpacked);
    }

    info!("Ok");

    Ok(())
}
