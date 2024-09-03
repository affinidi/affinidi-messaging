use std::time::SystemTime;

use atn_atm_sdk::{
    config::Config, conversions::secret_from_str, errors::ATMError, messages::GetMessagesRequest,
    protocols::Protocols, ATM,
};
use atn_did_cache_sdk::{config::ClientConfigBuilder, DIDCacheClient};
use clap::Parser;
use serde_json::json;
use tracing::info;
use tracing_subscriber::filter;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// network address if running in network mode (ws://127.0.0.1:8080/did/v1/ws)
    #[arg(short, long)]
    network_address: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), ATMError> {
    let args = Args::parse();
    // construct a subscriber that prints formatted traces to stdout
    let subscriber = tracing_subscriber::fmt()
        // Use a more compact, abbreviated log format
        .with_env_filter(filter::EnvFilter::from_default_env())
        .finish();
    // use that subscriber to process traces emitted after this point
    tracing::subscriber::set_global_default(subscriber).expect("Logging failed, exiting...");

    let my_did = "did:peer:2.Vz6MkgWJfVmPELozq6aCycK3CpxHN8Upphn3WSuQkWY6iqsjF.EzQ3shfb7vwQaTJqFkt8nRfo7Nu98tmeYpdDfWgrqQitDaqXRz";
    // Signing and verification key
    let v1 = json!({
        "crv": "Ed25519",
        "d": "LLWCf83n8VsUYq31zlZRe0NNMCcn1N4Dh85dGpIqSFw",
        "kty": "OKP",
        "x": "Hn8T4ZjjT0oJ6rjhqox8AykwC3GDFsJF6KkaYZExwQo"
    });

    // Encryption key
    let e1 = json!({
      "crv": "secp256k1",
      "d": "oi-dXG4EqfNODFPjv2vkieoLdbQZH9k6dwPDV8HDoms",
      "kty": "EC",
      "x": "DhfaXbhwo0KkOiyA5V1K1RZx6Ikr86h_lX5GOwxjmjE",
      "y": "PpYqybOwMsm64vftt-7gBCQPIUbglMmyy_6rloSSAPk"
    });

    let atm_did = "did:peer:2.Vz6MkiToqovww7vYtxm1xNM15u9JzqzUFZ1k7s7MazYJUyAxv.EzQ3shQLqRUza6AMJFbPuMdvFRFWm1wKviQRnQSC1fScovJN4s.SeyJ0IjoiRElEQ29tbU1lc3NhZ2luZyIsInMiOnsidXJpIjoiaHR0cHM6Ly8xMjcuMC4wLjE6NzAzNyIsImEiOlsiZGlkY29tbS92MiJdLCJyIjpbXX19";

    // ATM SDK supports an externally created DID Cache Resolver
    let did_resolver = DIDCacheClient::new(ClientConfigBuilder::default().build())
        .await
        .expect("Couldn't create DID Resolver!");

    let mut config = Config::builder()
        .with_ssl_certificates(&mut vec![
            "../atn-atm-mediator/conf/keys/client.chain".into()
        ])
        .with_my_did(my_did)
        .with_atm_did(atm_did)
        .with_websocket_disabled()
        .with_external_did_resolver(&did_resolver);
    /*
    // Use this to connect to the mediator
    // TODO: in the future we likely want to pull this from the DID itself
    .with_atm_api(
        "http://msg-de-msgfa-zqhvcom3qgjl-47801559.ap-southeast-1.elb.amazonaws.com:80/atm/v1",
    ).with_non_ssl()*/

    if let Some(address) = &args.network_address {
        println!("Running in network mode with address: {}", address);
        config = config.with_atm_api(address);
    } else {
        println!("Running in local mode.");
    }

    // Create a new ATM Client
    let mut atm = ATM::new(config.build()?).await?;
    let protocols = Protocols::new();

    // Add our secrets to ATM Client - stays local.
    atm.add_secret(secret_from_str(&format!("{}#key-1", my_did), &v1));
    atm.add_secret(secret_from_str(&format!("{}#key-2", my_did), &e1));

    // Ready to send a trust-ping to ATM
    let start = SystemTime::now();

    // You normally don't need to call authenticate() as it is called automatically
    // We do this here so we can time the auth cycle
    atm.authenticate().await?;
    let after_auth = SystemTime::now();

    // Send a trust-ping message to ATM, will generate a PONG response
    let response = protocols
        .trust_ping
        .send_ping(&mut atm, atm_did, true, true)
        .await?;
    let after_ping = SystemTime::now();

    info!("PING sent: {}", response.message_hash);

    // Get the PONG message from ATM
    let msgs = atm
        .get_messages(&GetMessagesRequest {
            delete: false,
            message_ids: vec![response.response.unwrap()],
        })
        .await?;
    let after_get = SystemTime::now();

    // Unpack the messages retrieved
    for msg in msgs.success {
        atm.unpack(&msg.msg.unwrap()).await?;
        info!("PONG received: {}", msg.msg_id);
    }
    let after_unpack = SystemTime::now();

    // Print out timing information
    info!(
        "Authenticating took {}ms :: total {}ms to complete",
        after_auth.duration_since(start).unwrap().as_millis(),
        after_auth.duration_since(start).unwrap().as_millis()
    );
    info!(
        "Sending Ping took {}ms :: total {}ms to complete",
        after_ping.duration_since(after_auth).unwrap().as_millis(),
        after_ping.duration_since(start).unwrap().as_millis()
    );
    info!(
        "Get response took {}ms :: total {}ms to complete",
        after_get.duration_since(after_ping).unwrap().as_millis(),
        after_get.duration_since(start).unwrap().as_millis()
    );
    info!(
        "Unpack took {}ms :: total {}ms to complete",
        after_unpack.duration_since(after_get).unwrap().as_millis(),
        after_unpack.duration_since(start).unwrap().as_millis()
    );
    info!(
        "Total trust-ping took {}ms to complete",
        after_unpack.duration_since(start).unwrap().as_millis()
    );

    /*
    // Send a WebSocket message
    info!("Starting WebSocket test...");
    let start = SystemTime::now();
    atm.start_websocket_task().await?;
    let after_websocket = SystemTime::now();

    let response = protocols
        .trust_ping
        .send_ping(&mut atm, atm_did, true, true)
        .await?;
    let after_ping = SystemTime::now();

    info!("PING sent: {}", response.message_hash);

    // Print out timing information
    info!(
        "Creating WebSocket took {}ms :: total {}ms to complete",
        after_websocket.duration_since(start).unwrap().as_millis(),
        after_websocket.duration_since(start).unwrap().as_millis()
    );

    info!(
        "Sending Ping took {}ms :: total {}ms to complete",
        after_ping
            .duration_since(after_websocket)
            .unwrap()
            .as_millis(),
        after_ping.duration_since(start).unwrap().as_millis()
    );*/

    Ok(())
}
