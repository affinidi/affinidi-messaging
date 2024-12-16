//! Example of how to manage administration accounts for the mediator
use affinidi_messaging_helpers::common::{
    affinidi_logo::print_logo,
    check_path,
    profiles::{Profile, Profiles},
};
use affinidi_messaging_mediator::common::config::ACLMode;
use affinidi_messaging_sdk::{config::Config, protocols::Protocols, ATM};
use clap::Parser;
use console::{style, Style, Term};
use dialoguer::theme::ColorfulTheme;
use global_acls::global_acls_menu;
use serde::Deserialize;
use serde_json::Value;
use sha256::digest;
use std::error::Error;
use std::{collections::HashMap, env};
use tracing_subscriber::filter;
use ui::{add_admin, list_admins, main_menu, remove_admins};

mod global_acls;
mod ui;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    profile: Option<String>,
}

/// Holds information from the mediator configuration
#[derive(Debug, Deserialize)]
struct BasicMediatorConfig {
    pub version: String,
    pub root_admin_did: String,
    pub acl_mode: ACLMode,
}

impl BasicMediatorConfig {
    // Converts and loads a retrieved configuration into a basic config structure
    pub fn new(input: HashMap<String, Value>) -> Result<Self, Box<dyn Error>> {
        let version = if let Some(version) = input.get("version") {
            if let Some(version) = version.as_str() {
                version.to_string()
            } else {
                return Err("Couldn't find version in Mediator Configuration".into());
            }
        } else {
            return Err("Couldn't find version in Mediator Configuration".into());
        };

        let config = if let Some(config) = input.get("config") {
            match serde_json::from_value::<HashMap<String, Value>>(config.to_owned()) {
                Ok(config) => config,
                Err(_) => return Err("Couldn't parse Mediator Configuration".into()),
            }
        } else {
            return Err("Couldn't parse Mediator Configuration".into());
        };

        let root_admin_did = if let Some(root_admin_did) = config.get("admin_did") {
            if let Some(root_admin_did) = root_admin_did.as_str() {
                root_admin_did.to_string()
            } else {
                return Err("Couldn't find admin_did in Mediator Configuration".into());
            }
        } else {
            return Err("Couldn't find admin_did in Mediator Configuration".into());
        };

        let acl_mode = if let Some(acl_mode) = config
            .get("security")
            .and_then(|security| security.get("acl_mode"))
        {
            match serde_json::from_value::<ACLMode>(acl_mode.to_owned()) {
                Ok(acl_mode) => acl_mode,
                Err(_) => return Err("Couldn't find acl_mode in Mediator Configuration".into()),
            }
        } else {
            return Err("Couldn't find admin_did in Mediator Configuration".into());
        };

        Ok(BasicMediatorConfig {
            version,
            root_admin_did,
            acl_mode,
        })
    }
}

async fn init() -> Result<(ColorfulTheme, Config, Profile), Box<dyn Error>> {
    let args: Args = Args::parse();

    let (profile_name, profile) = Profiles::smart_load(args.profile, env::var("AM_PROFILE").ok())?;
    println!("Using Profile: {}", profile_name);

    // construct a subscriber that prints formatted traces to stdout
    let subscriber = tracing_subscriber::fmt()
        // Use a more compact, abbreviated log format
        .with_env_filter(filter::EnvFilter::from_default_env())
        .finish();
    // use that subscriber to process traces emitted after this point
    tracing::subscriber::set_global_default(subscriber).expect("Logging failed, exiting...");

    let term = Term::stdout();
    let _ = term.clear_screen();
    print_logo();

    let theme = ColorfulTheme {
        values_style: Style::new().yellow().dim(),
        ..ColorfulTheme::default()
    };

    // determine the right path to config files
    check_path()?;

    println!(
        "{}",
        style("Welcome to the Affinidi Messaging Mediator Administration wizard").green(),
    );

    if profile.admin_did.is_none() {
        return Err("Admin DID not found in Profile".into());
    }

    let mut ssl_certificates = Vec::new();
    if let Some(ssl_certificate) = &profile.ssl_certificate {
        ssl_certificates.push(ssl_certificate.to_string());
    }

    // Connect to the Mediator
    let config = Config::builder()
        .with_ssl_certificates(&mut ssl_certificates)
        .build()?;

    Ok((theme, config, profile))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let (theme, config, profile) = init().await?;

    let admin = if let Some(admin) = profile.admin_did {
        admin
    } else {
        return Err("Admin DID not found in Profile".into());
    };

    let admin_hash = digest(&admin.did);

    // Create a new ATM Client
    let atm = ATM::new(config).await?;
    let protocols = Protocols::new();

    // Create the admin profile and enable it

    let admin_profile = admin.into_profile(&atm).await?;
    let admin = atm.profile_add(&admin_profile, true).await?;

    println!("{}", style("Admin account connected...").green());

    println!("{}", style("Fetching Mediator Configuration...").blue());
    let mediator_config: HashMap<String, Value> =
        serde_json::from_value(protocols.mediator.get_config(&atm, &admin).await?)?;
    let mediator_config = BasicMediatorConfig::new(mediator_config)?;
    println!(
        "{}{}{}",
        style("Mediator version(").green(),
        style(&mediator_config.version).color256(208),
        style("). Configuration loaded successfully").green()
    );

    loop {
        println!();
        let selection = main_menu(&theme);

        println!();
        match selection {
            0 => {
                list_admins(
                    &atm,
                    &admin,
                    &protocols,
                    &admin_hash,
                    &digest(&mediator_config.root_admin_did),
                )
                .await
            }
            1 => add_admin(&atm, &admin, &protocols, &theme).await,
            2 => remove_admins(&atm, &admin, &protocols, &admin_hash, &theme).await,
            3 => global_acls_menu(&atm, &admin, &protocols, &theme, &mediator_config).await?,
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
