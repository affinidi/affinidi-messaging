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
use tokio::time::sleep;
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

    let built = alice_config.build()?;
    // Create a new ATM Client
    let mut alice_atm = ATM::new(built.clone()).await?;
    let mut alice2_atm = ATM::new(built.clone()).await?;

    sleep(Duration::from_secs(30)).await;

    Ok(())
}
