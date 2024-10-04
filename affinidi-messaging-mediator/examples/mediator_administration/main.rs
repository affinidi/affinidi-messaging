//! Example of how to manage administration accounts for the mediator
use affinidi_messaging_didcomm::secrets::Secret;
use affinidi_messaging_mediator::common;
use affinidi_messaging_sdk::{config::Config, protocols::Protocols, ATM};
use console::{style, Style, Term};
use dialoguer::{theme::ColorfulTheme, Select};
use sha256::digest;
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use tracing_subscriber::filter;

mod affinidi_logo;

/// Returns the path to the mediator directory depending on where you are
fn check_path() -> Result<String, Box<dyn Error>> {
    let cwd = std::env::current_dir()?;
    let mut path = String::new();
    let mut found = false;
    cwd.components().rev().for_each(|dir| {
        if dir.as_os_str() == "affinidi-messaging" && !found {
            found = true;
            path.push_str("affinidi-messaging-mediator/");
        } else if dir.as_os_str() == "affinidi-messaging-mediator" && !found {
            found = true;
            path.push_str("./");
        } else if !found {
            path.push_str("../");
        }
    });

    if !found {
        return Err("You are not in the affinidi-messaging repository".into());
    }

    Ok(path)
}

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

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
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

    println!(
        "{}",
        style("Welcome to the Affinidi Messaging Mediator Administration wizard").green(),
    );

    // determine the right path to config files
    let path = check_path()?;
    env::set_current_dir(&path)?;

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
        .with_ssl_certificates(&mut vec![client_cert_chain]);

    // Create a new ATM Client
    let mut atm = ATM::new(config.build()?).await?;
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

    let selections = &[
        "List Administration DIDs",
        "Add new Administration DID",
        "Remove Administration DID",
        "Quit",
    ];

    println!();
    loop {
        let selection = Select::with_theme(&theme)
            .with_prompt("Select an action?")
            .default(0)
            .items(&selections[..])
            .interact()
            .unwrap();

        println!();
        match selection {
            0 => match protocols.mediator.list_admins(&mut atm, None, None).await {
                Ok(admins) => {
                    println!(
                        "{}",
                        style("Listing Administration DIDs (SHA256 Hashed DID's)").green()
                    );

                    for (idx, admin) in admins.admins.iter().enumerate() {
                        print!("  {}", style(format!("{}: {}", idx, admin)).yellow());
                        if admin == &root_admin_hash {
                            println!(" {}", style(" mediator_root").red());
                        } else {
                            println!();
                        }
                    }
                }
                Err(e) => {
                    println!("{}", style(format!("Error: {}", e)).red());
                }
            },
            1 => {
                println!("Adding new Administration DID");
            }
            2 => {
                println!("Removing Administration DID");
            }
            3 => {
                println!("Quitting");
                break;
            }
            _ => {
                println!("Invalid selection");
            }
        }

        println!();
    }

    Ok(())
}
