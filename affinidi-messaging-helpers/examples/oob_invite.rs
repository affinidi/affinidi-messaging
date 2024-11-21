//! Example using OOB Discovery to create and retrieve an invitation
//! Does not show the next steps of creating the connection, this is outside of the scope of this example

use affinidi_messaging_helpers::common::profiles::Profiles;
use affinidi_messaging_sdk::{
    config::Config, errors::ATMError, profiles::Profile, protocols::Protocols, ATM,
};
use clap::Parser;
use std::env;
use tracing::debug;
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
    let p_alice = Profile::new(
        &atm,
        Some("Alice".to_string()),
        alice.did.clone(),
        Some(profile.mediator_did.clone()),
        alice.keys.clone(), // alice.keys.clone(),
    )
    .await?;

    debug!("Enabling Alice's Profile");

    // add and enable the profile
    let alice = atm.profile_add(&p_alice, true).await?;

    println!("Creating Bob's Profile");
    let p_bob = Profile::new(
        &atm,
        Some("Bob".to_string()),
        bob.did.clone(),
        Some(profile.mediator_did.clone()),
        bob.keys.clone(), // alice.keys.clone(),
    )
    .await?;

    debug!("Enabling Bob's Profile");

    // add and enable the profile
    let _bob = atm.profile_add(&p_bob, true).await?;

    let oob_id = protocols
        .oob_discovery
        .create_invite(&atm, &alice, None)
        .await?;

    println!("oob_id = {}", oob_id);
    println!();

    let endpoint = if let Some(mediator) = &*alice.inner.mediator {
        mediator.rest_endpoint.as_ref().unwrap().to_string()
    } else {
        panic!("Alice's mediator is not set");
    };

    let url = [&endpoint, "/oob?_oobid=", &oob_id].concat();
    println!("Attempting to retrieve an invitation: {}", url);
    let invitation = protocols.oob_discovery.retrieve_invite(&atm, &url).await?;

    println!(
        "Received invitation:\n{}",
        serde_json::to_string_pretty(&invitation).unwrap()
    );

    println!();
    let del_response = protocols
        .oob_discovery
        .delete_invite(&atm, &alice, &oob_id)
        .await?;

    println!("Delete response: deleted? {}", del_response);

    Ok(())
}
