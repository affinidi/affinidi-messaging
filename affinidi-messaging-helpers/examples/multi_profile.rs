//! Sends a message from Alice to Bob and then retrieves it.

use affinidi_messaging_helpers::common::profiles::Profiles;
use affinidi_messaging_sdk::{config::ConfigBuilder, errors::ATMError, profiles::Profile, ATM};
use clap::Parser;
use std::{env, time::Duration};
use tokio::time::sleep;
use tracing_subscriber::filter;

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

    println!("Start ATM");

    let atm = ATM::new(ConfigBuilder::default().build()?).await?;

    println!("Creating Alice's Profile");
    let p = Profile::new(
        &atm,
        Some("Alice".to_string()),
        alice.did.clone(),
        Some(profile.mediator_did),
        alice.keys.clone(), // alice.keys.clone(),
    )
    .await?;

    println!("Created Alice's Profile");

    // add and enable the profile
    let _ = atm.profile_add(&p, true).await;

    println!("Added Alice's Profile");

    sleep(Duration::from_secs(5)).await;
    Ok(())
}
