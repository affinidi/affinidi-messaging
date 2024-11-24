use affinidi_messaging_didcomm::{Message, MessageBuilder};
use affinidi_messaging_helpers::common::profiles::Profiles;
use affinidi_messaging_sdk::{
    config::Config,
    errors::ATMError,
    messages::{
        fetch::FetchOptions, sending::InboundMessageResponse, DeleteMessageRequest,
        FetchDeletePolicy, Folder, GetMessagesRequest,
    },
    profiles::Profile,
    protocols::Protocols,
    transports::SendMessageResponse,
    ATM,
};
use clap::Parser;
use serde_json::json;
use std::{
    env,
    time::{Duration, SystemTime},
};
use tokio::time::sleep;
use tracing::{debug, error, info};
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

    let mut config = Config::builder();

    if let Some(ssl_cert) = &profile.ssl_certificate {
        config = config.with_ssl_certificates(&mut vec![ssl_cert.to_string()]);
        println!("Using SSL Certificate: {}", ssl_cert);
    }

    // Create a new ATM Client
    let atm = ATM::new(config.build()?).await?;
    let protocols = Protocols::new();

    println!("Creating Alice's Profile");
    let p = Profile::new(
        &atm,
        Some("Alice".to_string()),
        alice.did.clone(),
        Some(profile.mediator_did.clone()),
        alice.keys.clone(), // alice.keys.clone(),
    )
    .await?;

    debug!("Enabling Alice's Profile");

    // add and enable the profile
    let alice = atm.profile_add(&p, false).await?;

    println!("Creating Bob's Profile");
    let p = Profile::new(
        &atm,
        Some("Bob".to_string()),
        bob.did.clone(),
        Some(profile.mediator_did.clone()),
        bob.keys.clone(), // alice.keys.clone(),
    )
    .await?;

    debug!("Enabling Bob's Profile");

    // add and enable the profile
    let bob = atm.profile_add(&p, false).await?;

    // Delete all messages for Alice
    let response = atm
        .fetch_messages(
            &alice,
            &FetchOptions {
                limit: 100,
                delete_policy: FetchDeletePolicy::Optimistic,
                start_id: None,
            },
        )
        .await?;

    println!(
        "Alice existing messages ({}). Deleted all...",
        response.success.len()
    );

    // Delete all messages for Bob
    let response = atm
        .fetch_messages(
            &bob,
            &FetchOptions {
                limit: 100,
                delete_policy: FetchDeletePolicy::Optimistic,
                start_id: None,
            },
        )
        .await?;

    println!(
        "Bob existing messages ({}). Deleted all...",
        response.success.len()
    );

    // Send a message to Alice from Bob

    let message = MessageBuilder::new(
        Uuid::new_v4().to_string(),
        "test".to_string(),
        json!("Hello Alice"),
    )
    .from(bob.inner.did.clone())
    .to(alice.inner.did.clone())
    .finalize();

    let msg_id = message.id.clone();

    // Pack the message
    let packed = atm
        .pack_encrypted(
            &message,
            &alice.inner.did,
            Some(&bob.inner.did),
            Some(&bob.inner.did),
        )
        .await?;

    let forward = protocols
        .routing
        .forward_message(
            &atm,
            &bob,
            &packed.0,
            &profile.mediator_did,
            &alice.inner.did,
            None,
            None,
        )
        .await?;

    println!(
        "Bob --> ALice msg_id({}) :: Bob --> Mediator forward msg_id({})",
        msg_id, forward.0,
    );

    atm.send_message(&bob, &forward.1, &forward.0, false)
        .await?;

    println!("Bob sent Alice a message");

    // See if Alice has a message waiting
    let response = atm.fetch_messages(&alice, &FetchOptions::default()).await?;

    println!(
        "Alice new message msg_id({})",
        response.success.first().unwrap().msg_id
    );

    let new_msg_id = response.success.first().unwrap().msg_id.clone();

    // See if Bob has a message waiting
    let response = atm.list_messages(&bob, Folder::Outbox).await?;

    println!(
        "Bob sent message msg_id({})",
        response.first().unwrap().msg_id
    );

    // Try to delete a fake message
    let response = atm
        .delete_messages(
            &alice,
            &DeleteMessageRequest {
                message_ids: vec!["fake".to_string()],
            },
        )
        .await?;

    println!("Delete fake message: {:#?}", response);

    // Try to delete a real message
    let response = atm
        .delete_messages(
            &alice,
            &DeleteMessageRequest {
                message_ids: vec![new_msg_id],
            },
        )
        .await?;

    println!("Deleted real message: {:#?}", response);

    Ok(())
}
