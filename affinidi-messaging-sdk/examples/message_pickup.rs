use std::time::Duration;

use affinidi_messaging_sdk::{
    config::Config, conversions::secret_from_str, errors::ATMError, protocols::Protocols, ATM,
};
use clap::Parser;
use serde_json::json;
use tracing::info;
use tracing_subscriber::filter;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    network_address: String,
    #[arg(short, long)]
    ssl_certificates: String,
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

    let public_config_builder = Config::builder()
        .with_atm_api(&args.network_address)
        .with_ssl_certificates(&mut vec![args.ssl_certificates.clone().into()])
        .with_websocket_disabled();

    let mut public_atm = ATM::new(public_config_builder.build()?).await?;

    let atm_did = public_atm.well_known_did().await?;


    let mut config = Config::builder().with_my_did(my_did).with_atm_did(&atm_did);

    println!("Running with address: {}", &args.network_address);
    config = config
        .with_atm_api(&args.network_address)
        .with_ssl_certificates(&mut vec![args.ssl_certificates.into()]);

    // Create a new ATM Client
    let mut atm = ATM::new(config.build()?).await?;

    // Add our secrets to ATM Client - stays local.
    atm.add_secret(secret_from_str(&format!("{}#key-1", my_did), &v1));
    atm.add_secret(secret_from_str(&format!("{}#key-2", my_did), &e1));

    info!("Authenticate and establish websocket connection");
    atm.start_websocket_task().await?;

    info!("toggle_live_delivery");
    let protocols = Protocols::new();
    // Enable live streaming
    protocols
        .message_pickup
        .toggle_live_delivery(&mut atm, true)
        .await?;

    // Send a Message Pickup 3.0 Status Request
    info!("Testing live_stream_next()!");
    let status = protocols
        .message_pickup
        .send_status_request(&mut atm, None, None, None)
        .await?;

    info!("Status: {:?}", status);

    if let Some((message, _)) = protocols
        .message_pickup
        .live_stream_next(&mut atm, Duration::from_secs(2))
        .await?
    {
        info!("[live_stream_next] Message: {:?}", message);
    }

    info!("Testing delivery-request()!");
    let response = protocols
        .message_pickup
        .send_delivery_request(&mut atm, None, None, None, None)
        .await?;

    let mut delete_ids: Vec<String> = Vec::new();

    for (message, _) in response {
        info!("[send_delivery_request] Message: {}", message.id);
        delete_ids.push(message.id.clone());
    }

    let response = protocols
        .message_pickup
        .send_messages_received(&mut atm, None, None, &delete_ids, None)
        .await?;

    info!("Status: after send_messages_received() : {:?}", response);

    /* TODO: Need to complete this part of the protocol...

    tokio::time::sleep(Duration::from_secs(1)).await;
    error!("Testing live_stream_get()!");

    let response = protocols
        .message_pickup
        .send_status_request(&mut atm, None, None, None)
        .await?;

    info!("Status: {:?}", response);
    */

    // Disable live streaming
    protocols
        .message_pickup
        .toggle_live_delivery(&mut atm, false)
        .await?;

    tokio::time::sleep(Duration::from_secs(1)).await;

    atm.abort_websocket_task().await?;

    Ok(())
}
