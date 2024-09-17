use affinidi_messaging_sdk::{config::Config, conversions::secret_from_str, errors::ATMError, ATM};
use clap::{command, Parser};
use serde_json::{json, Value};
use std::error::Error;
use tracing::info;
use tracing_subscriber::filter;

pub struct ExampleActorConfiguration {
    pub verification_key: Value,
    pub encryption_key: Value,
    pub did: String,
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    network_address: String,
    #[arg(short, long)]
    ssl_certificates: String,
    #[arg(short, long)]
    mediator_did: String,
}

pub struct ConfigureAtmResult {
    pub atm: ATM<'static>,
    pub atm_did: String,
    pub actor_did: String,
}

pub fn alice_configuration() -> ExampleActorConfiguration {
    ExampleActorConfiguration {
        verification_key: json!({
            "crv": "Ed25519",
            "d": "LLWCf83n8VsUYq31zlZRe0NNMCcn1N4Dh85dGpIqSFw",
            "kty": "OKP",
            "x": "Hn8T4ZjjT0oJ6rjhqox8AykwC3GDFsJF6KkaYZExwQo"
        }),
        encryption_key: json!({
            "crv": "secp256k1",
            "d": "oi-dXG4EqfNODFPjv2vkieoLdbQZH9k6dwPDV8HDoms",
            "kty": "EC",
            "x": "DhfaXbhwo0KkOiyA5V1K1RZx6Ikr86h_lX5GOwxjmjE",
            "y": "PpYqybOwMsm64vftt-7gBCQPIUbglMmyy_6rloSSAPk"
        }),
        did: String::from("did:peer:2.Vz6MkgWJfVmPELozq6aCycK3CpxHN8Upphn3WSuQkWY6iqsjF.EzQ3shfb7vwQaTJqFkt8nRfo7Nu98tmeYpdDfWgrqQitDaqXRz"),
    }
}

pub fn bob_configuration() -> ExampleActorConfiguration {
    ExampleActorConfiguration {
        verification_key: json!({
            "crv": "Ed25519",
            "d": "FZMJijqdcp7PCQShgtFj6Ud3vjZY7jFZBVvahziaMMM",
            "kty": "OKP",
            "x": "PybG95kyeSfGRebp4T7hzA7JQuysc6mZ97nM2ety6Vo"
        }),
        encryption_key: json!({
            "crv": "secp256k1",
            "d": "ai7B5fgT3pCBHec0I4Y1xXpSyrEHlTy0hivSlddWHZE",
            "kty": "EC",
            "x": "k2FhEi8WMxr4Ztr4u2xjKzDESqVnGg_WKrN1820wPeA",
            "y": "fq0DnZ_duPWyeFK0k93bAzjNJVVHEjHFRlGOJXKDS18"
        }),
        did: String::from("did:peer:2.Vz6Mkihn2R3M8nY62EFJ7MAVXu7YxsTnuS5iAhmn3qKJbkdFf.EzQ3shpZRBUtewwzYiueXgDqs1bvGNkSyGoRgsbZJXt3TTb9jD.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHBzOi8vbG9jYWxob3N0OjcwMzcvIiwiYWNjZXB0IjpbImRpZGNvbW0vdjIiXSwicm91dGluZ19rZXlzIjpbXX0sImlkIjpudWxsfQ"),
    }
}

pub async fn configure_atm(
    example_configuration: ExampleActorConfiguration,
) -> Result<ConfigureAtmResult, ATMError> {
    // **************************************************************
    // *** Initial setup
    // **************************************************************
    let args = Args::parse();

    // construct a subscriber that prints formatted traces to stdout
    let subscriber = tracing_subscriber::fmt()
        // Use a more compact, abbreviated log format
        .with_env_filter(filter::EnvFilter::from_default_env())
        .finish();
    // use that subscriber to process traces emitted after this point
    tracing::subscriber::set_global_default(subscriber).expect("Logging failed, exiting...");

    info!("Running with address: {}", &args.network_address);
    info!("Running with mediator_did: {}", &args.mediator_did);
    info!("Running with ssl_certificates: {}", &args.ssl_certificates);

    let atm_did = &args.mediator_did;

    // TODO: in the future we likely want to pull this from the DID itself
    let mut config = Config::builder()
        .with_my_did(&example_configuration.did)
        .with_atm_did(atm_did)
        .with_websocket_disabled();

    config = config
        .with_atm_api(&args.network_address)
        .with_ssl_certificates(&mut vec![args.ssl_certificates.into()]);

    // Create a new ATM Client
    let mut atm = ATM::new(config.build()?).await?;

    // Add our secrets to ATM Client - stays local.
    atm.add_secret(secret_from_str(
        &format!("{}#key-1", &example_configuration.did),
        &example_configuration.verification_key,
    ));
    atm.add_secret(secret_from_str(
        &format!("{}#key-2", &example_configuration.did),
        &example_configuration.encryption_key,
    ));

    Ok(ConfigureAtmResult {
        atm,
        atm_did: atm_did.clone(),
        actor_did: example_configuration.did,
    })
}

pub async fn configure_alice_atm() -> Result<ConfigureAtmResult, ATMError> {
    configure_atm(alice_configuration()).await
}

pub async fn configure_bob_atm() -> Result<ConfigureAtmResult, ATMError> {
    configure_atm(bob_configuration()).await
}

// to avoid: error[E0601]: `main` function not found in crate `common`
fn main() {
    info!("Please use examples for check affinidi-messaging-sdk functionality.");
}
