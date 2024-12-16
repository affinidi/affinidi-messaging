//! Example using OOB Discovery to create and retrieve an invitation
//! Does not show the next steps of creating the connection, this is outside of the scope of this example

use affinidi_messaging_helpers::common::profiles::Profiles;
use affinidi_messaging_sdk::{config::Config, errors::ATMError, protocols::Protocols, ATM};
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

    let mut config = Config::builder();

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
