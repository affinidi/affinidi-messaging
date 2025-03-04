use affinidi_messaging_didcomm::MessageBuilder;
use affinidi_messaging_helpers::common::profiles::Profiles;
use affinidi_messaging_sdk::{
    ATM,
    config::ATMConfig,
    errors::ATMError,
    messages::{DeleteMessageRequest, FetchDeletePolicy, Folder, fetch::FetchOptions},
    profiles::ProfileConfig,
    protocols::Protocols,
};
use clap::Parser;
use serde_json::json;
use std::env;
use tracing::debug;
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

    let mut config = ATMConfig::builder();

    if let Some(ssl_cert) = &profile.ssl_certificate {
        config = config.with_ssl_certificates(&mut vec![ssl_cert.to_string()]);
        println!("Using SSL Certificate: {}", ssl_cert);
    }

    // Create a new ATM Client
    let atm = ATM::new(config.build()?).await?;
    let protocols = Protocols::new();

    debug!("Enabling Alice's Profile");
    let alice = atm
        .profile_add(&alice.into_profile(&atm).await?, true)
        .await?;

    debug!("Enabling Bob's Profile");
    let bob = atm
        .profile_add(&bob.into_profile(&atm).await?, true)
        .await?;

    // Ensure Profile has a valid mediator to forward through
    let mediator_did = if let Some(mediator) = profile.default_mediator {
        mediator.clone()
    } else {
        return Err(ATMError::ConfigError(
            "Profile Mediator not found".to_string(),
        ));
    };

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
            &mediator_did,
            &alice.inner.did,
            None,
            None,
        )
        .await?;

    println!(
        "Bob --> ALice msg_id({}) :: Bob --> Mediator forward msg_id({})",
        msg_id, forward.0,
    );

    atm.send_message(&bob, &forward.1, &forward.0, false, false)
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
        .delete_messages_direct(
            &alice,
            &DeleteMessageRequest {
                message_ids: vec!["fake".to_string()],
            },
        )
        .await?;

    println!("Delete fake message: {:#?}", response);

    // Try to delete a real message
    let response = atm
        .delete_messages_direct(
            &alice,
            &DeleteMessageRequest {
                message_ids: vec![new_msg_id],
            },
        )
        .await?;

    println!("Deleted real message: {:#?}", response);

    println!(" **** ");
    let profiles = ProfileConfig::from_profiles(&*atm.get_profiles().read().await).await;

    println!("{}", serde_json::to_string_pretty(&profiles).unwrap());

    Ok(())
}
