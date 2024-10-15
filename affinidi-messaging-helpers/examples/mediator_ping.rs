//! Example Trust Ping using the Affinidi Trust Messaging SDK
//! Pings the mediator from Alice
//! Will use HTTPS and then WebSocket

use affinidi_messaging_helpers::common::profiles::Profiles;
use affinidi_messaging_sdk::{
    config::Config, errors::ATMError, messages::GetMessagesRequest, protocols::Protocols, ATM,
};
use clap::Parser;
use std::{env, time::SystemTime};
use tracing::info;
use tracing_subscriber::filter;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    profile: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), ATMError> {
    let args = Args::parse();

    let (profile_name, profile) = Profiles::smart_load(args.profile, env::var("AM_PROFILE").ok())
        .map_err(|err| ATMError::ConfigError(err.to_string()))?;
    println!("Using Profile: {}", profile_name);

    // construct a subscriber that prints formatted traces to stdout
    let subscriber = tracing_subscriber::fmt()
        // Use a more compact, abbreviated log format
        .with_env_filter(filter::EnvFilter::from_default_env())
        .finish();
    // use that subscriber to process traces emitted after this point
    tracing::subscriber::set_global_default(subscriber).expect("Logging failed, exiting...");

    let alice = if let Some(alice) = profile.friends.get("Alice") {
        alice
    } else {
        return Err(ATMError::ConfigError(
            format!("Alice not found in Profile: {}", profile_name).to_string(),
        ));
    };

    let mut config = Config::builder()
        .with_my_did(&alice.did)
        .with_atm_did(&profile.mediator_did)
        .with_websocket_disabled()
        .with_atm_api(&profile.network_address);

    if let Some(ssl_cert) = &profile.ssl_certificate {
        config = config.with_ssl_certificates(&mut vec![ssl_cert.to_string()]);
        println!("Using SSL Certificate: {}", ssl_cert);
    }

    // Create a new ATM Client
    let mut atm = ATM::new(config.build()?).await?;
    let protocols = Protocols::new();

    // Add our secrets to ATM Client - stays local.
    atm.add_secret(alice.get_key("#key-1").unwrap());
    atm.add_secret(alice.get_key("#key-2").unwrap());

    // Ready to send a trust-ping to ATM
    let start = SystemTime::now();

    // You normally don't need to call authenticate() as it is called automatically
    // We do this here so we can time the auth cycle
    atm.authenticate().await?;

    let after_auth = SystemTime::now();

    // Send a trust-ping message to ATM, will generate a PONG response
    let response = protocols
        .trust_ping
        .send_ping(&mut atm, &profile.mediator_did, true, true)
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

    // Send a WebSocket message
    info!("Starting WebSocket test...");
    let start = SystemTime::now();
    atm.start_websocket_task().await?;
    let after_websocket = SystemTime::now();

    let response = protocols
        .trust_ping
        .send_ping(&mut atm, &profile.mediator_did, true, true)
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
    );

    Ok(())
}
