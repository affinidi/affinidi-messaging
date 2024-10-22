//! Sends a message from Alice to Bob and then retrieves it.

use affinidi_messaging_didcomm::Message;
use affinidi_messaging_helpers::common::profiles::Profiles;
use affinidi_messaging_sdk::{
    config::Config, errors::ATMError, messages::EmptyResponse, protocols::Protocols, ATM,
};
use clap::Parser;
use serde_json::json;
use std::{
    env,
    time::{Duration, SystemTime},
};
use tracing::{error, info};
use tracing_subscriber::filter;
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    profile: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), ATMError> {
    let args: Args = Args::parse();

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

    let bob = if let Some(bob) = profile.friends.get("Bob") {
        bob
    } else {
        return Err(ATMError::ConfigError(
            format!("Bob not found in Profile: {}", profile_name).to_string(),
        ));
    };

    let mut alice_config = Config::builder()
        .with_my_did(&alice.did)
        .with_atm_did(&profile.mediator_did)
        .with_secrets(alice.keys.clone())
        .with_atm_api(&profile.network_address);

    let mut bob_config = Config::builder()
        .with_my_did(&bob.did)
        .with_atm_did(&profile.mediator_did)
        .with_secrets(bob.keys.clone())
        .with_atm_api(&profile.network_address);

    if let Some(ssl_cert) = &profile.ssl_certificate {
        alice_config = alice_config.with_ssl_certificates(&mut vec![ssl_cert.to_string()]);
        bob_config = bob_config.with_ssl_certificates(&mut vec![ssl_cert.to_string()]);
        info!("Using SSL Certificate: {}", ssl_cert);
    } else {
        alice_config = alice_config.with_non_ssl();
        bob_config = bob_config.with_non_ssl();
        error!("  **** Not using SSL/TLS ****");
    }

    // Create a new ATM Client
    let mut alice_atm = ATM::new(alice_config.build()?).await?;
    let mut bob_atm = ATM::new(bob_config.build()?).await?;
    let protocols = Protocols::new();

    // Turn on live streaming for Bob
    protocols
        .message_pickup
        .toggle_live_delivery(&mut bob_atm, true)
        .await?;

    println!("Bob turned on live streaming");
    let start = SystemTime::now();

    // Create message from Alice to Bob
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let msg = Message::build(
        Uuid::new_v4().into(),
        "Chatty Alice".into(),
        json!("Hello Bob!"),
    )
    .to(bob.did.clone())
    .from(alice.did.clone())
    .created_time(now)
    .expires_time(now + 10)
    .finalize();

    let msg_id = msg.id.clone();

    println!(
        "Plaintext Message from Alice to Bob msg_id({}):\n {:#?}",
        msg_id, msg
    );
    println!();

    let packed_msg = alice_atm
        .pack_encrypted(&msg, &bob.did, Some(&alice.did), Some(&alice.did))
        .await?;

    println!(
        "Packed encrypted+signed message from Alice to Bob:\n{:#?}",
        packed_msg.0
    );

    println!();

    // Wrap it in a forward
    let forward_msg = protocols
        .routing
        .forward_message(
            &mut alice_atm,
            &packed_msg.0,
            &profile.mediator_did,
            &bob.did,
            None,
            None,
        )
        .await?;

    println!(
        "Forwarded message from Alice to Mediator:\n{:#?}",
        forward_msg
    );
    println!();

    // Send the message
    alice_atm
        .send_didcomm_message::<EmptyResponse>(&forward_msg, false)
        .await?;

    println!("Alice sent message to Bob");

    // Bob gets his messages
    println!();
    println!("Bob receiving messages");
    match protocols
        .message_pickup
        .live_stream_get(&mut bob_atm, &msg_id, Duration::from_secs(5))
        .await?
    {
        Some(msg) => {
            println!();
            println!(
                "Decrypted Message from Alice to Bob msg_id({}):\n {:#?}\n",
                msg_id, msg.0
            );
        }
        None => {
            println!("No messages found. Exiting...");
        }
    }

    let end = SystemTime::now();
    println!(
        "Forwarding Example took {}ms in total",
        end.duration_since(start).unwrap().as_millis(),
    );

    Ok(())
}
