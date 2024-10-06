//! Example of how to manage administration accounts for the mediator
use affinidi_messaging_didcomm::secrets::Secret;
use affinidi_messaging_mediator::common;
use affinidi_messaging_mediator::common::config::Config as MediatorConfig;
use affinidi_messaging_sdk::{config::Config, protocols::Protocols, ATM};
use console::{style, Style, Term};
use dialoguer::theme::ColorfulTheme;
use global_acls::global_acls_menu;
use sha256::digest;
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use tracing_subscriber::filter;
use ui::{add_admin, check_path, list_admins, main_menu, remove_admins};

mod affinidi_logo;
mod global_acls;
mod ui;

fn read_secrets_from_file<P: AsRef<Path>>(path: P) -> Result<Vec<Secret>, Box<dyn Error>> {
    // Open the file in read-only mode with buffer.
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let secrets = serde_json::from_reader(reader)?;
    Ok(secrets)
}

fn fix_ssl_path(path: &str) -> String {
    let _p = Path::new(path);
    let mut components: Vec<String> = _p
        .components()
        .map(|c| c.as_os_str().to_str().unwrap().to_string())
        .collect();
    components.pop();
    components.push("client.chain".to_string());

    components.join("/")
}

async fn init() -> Result<(ColorfulTheme, MediatorConfig, String, Config<'static>), Box<dyn Error>>
{
    // construct a subscriber that prints formatted traces to stdout
    let subscriber = tracing_subscriber::fmt()
        // Use a more compact, abbreviated log format
        .with_env_filter(filter::EnvFilter::from_default_env())
        .finish();
    // use that subscriber to process traces emitted after this point
    tracing::subscriber::set_global_default(subscriber).expect("Logging failed, exiting...");

    let term = Term::stdout();
    let _ = term.clear_screen();
    affinidi_logo::print_logo();

    let theme = ColorfulTheme {
        values_style: Style::new().yellow().dim(),
        ..ColorfulTheme::default()
    };

    // determine the right path to config files
    let path = check_path()?;
    env::set_current_dir(&path)?;

    println!(
        "{}",
        style("Welcome to the Affinidi Messaging Mediator Administration wizard").green(),
    );

    println!(
        "{} {}",
        style("Setting correct working directory to: ").yellow(),
        style(path).blue()
    );

    // Load the mediator configuration
    let mediator_config = common::config::init("conf/mediator.toml", None).await?;
    println!(
        "{}",
        style("Successfully read mediator configuration...").yellow()
    );

    let root_admin_hash = digest(&mediator_config.admin_did);

    // read secrets from file
    let secrets = read_secrets_from_file("conf/secrets-admin.json")?;
    println!(
        "{} {}",
        style("Admin secrets loaded successfully... admin DID:").yellow(),
        style(&mediator_config.admin_did).blue()
    );

    // Modify the SSL certificate path from server to client certificate chain
    let client_cert_chain = fix_ssl_path(&mediator_config.security.ssl_certificate_file);

    // Strip trailing `/` from the API prefix if it exists
    let api_prefix = if mediator_config.api_prefix.ends_with('/') {
        &mediator_config.api_prefix[..mediator_config.api_prefix.len() - 1]
    } else {
        &mediator_config.api_prefix
    };

    // Connect to the Mediator
    let config = Config::builder()
        .with_my_did(&mediator_config.admin_did)
        .with_atm_did(&mediator_config.mediator_did)
        .with_atm_api(&["https://", "127.0.0.1:7037", api_prefix].concat())
        .with_secrets(secrets)
        .with_ssl_certificates(&mut vec![client_cert_chain])
        .build()?;

    Ok((theme, mediator_config, root_admin_hash, config))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let (theme, mediator_config, root_admin_hash, config) = init().await?;
    // Create a new ATM Client
    let mut atm = ATM::new(config).await?;
    let protocols = Protocols::new();

    protocols
        .message_pickup
        .toggle_live_delivery(&mut atm, true)
        .await?;
    println!(
        "{}",
        style("Live Delivery enabled using MessagePickup Protocol via WebSocket transport...")
            .green()
    );

    loop {
        println!();
        let selection = main_menu(&theme);

        println!();
        match selection {
            0 => list_admins(&mut atm, &protocols, &root_admin_hash).await,
            1 => add_admin(&mut atm, &protocols, &theme).await,
            2 => remove_admins(&mut atm, &protocols, &root_admin_hash, &theme).await,
            3 => global_acls_menu(&mut atm, &protocols, &theme, &mediator_config).await,
            4 => {
                println!("Quitting");
                break;
            }
            _ => {
                println!("Invalid selection");
            }
        }
    }

    Ok(())
}
