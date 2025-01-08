//! Example of how to manage administration accounts for the mediator
use affinidi_messaging_helpers::common::{
    affinidi_logo::print_logo,
    check_path,
    profiles::{Profile, Profiles},
};
use affinidi_messaging_sdk::{
    config::Config,
    protocols::{
        mediator::acls::{ACLModeType, MediatorACLSet},
        Protocols,
    },
    ATM,
};
use clap::Parser;
use console::{style, Style, Term};
use dialoguer::{theme::ColorfulTheme, Select};
use global_acl_management::global_acls::account_management_menu;
use serde::Deserialize;
use serde_json::Value;
use sha256::digest;
use std::error::Error;
use std::{collections::HashMap, env};
use tracing_subscriber::filter;
use ui::administration_accounts_menu;

mod global_acl_management;
mod ui;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    profile: Option<String>,
}

/// Holds information from the mediator configuration
#[derive(Debug, Deserialize)]
struct SharedConfig {
    pub version: String,
    pub root_admin_hash: String,
    pub our_admin_hash: String,
    pub acl_mode: ACLModeType,
    pub global_acl_default: MediatorACLSet,
}

impl SharedConfig {
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
            .and_then(|security| security.get("mediator_acl_mode"))
        {
            match serde_json::from_value::<ACLModeType>(acl_mode.to_owned()) {
                Ok(acl_mode) => acl_mode,
                Err(_) => {
                    return Err("Couldn't find mediator_acl_mode in Mediator Configuration".into())
                }
            }
        } else {
            return Err("Couldn't find mediator_acl_mode in Mediator Configuration".into());
        };

        let global_acl_default = if let Some(global_acl_default) = config
            .get("security")
            .and_then(|security| security.get("global_acl_default"))
            .and_then(|acls| acls.get("acl"))
        {
            if let Some(global_acl_default) = global_acl_default.as_u64() {
                MediatorACLSet::from_u64(global_acl_default)
            } else {
                return Err("Couldn't find global_acl_default in Mediator Configuration".into());
            }
        } else {
            return Err("Couldn't find global_acl_default in Mediator Configuration".into());
        };

        Ok(SharedConfig {
            version,
            root_admin_hash: digest(&root_admin_did),
            acl_mode,
            global_acl_default,
            our_admin_hash: String::new(),
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

    // Create a new ATM Client
    let atm = ATM::new(config).await?;
    let protocols = Protocols::new();

    // Create the admin profile and enable it
    let admin_profile = admin.into_profile(&atm).await?;
    let admin = atm.profile_add(&admin_profile, true).await?;

    println!("{}", style("Admin account connected...").green());

    println!("{}", style("Fetching Mediator Configuration...").blue());
    let shared_config: HashMap<String, Value> =
        serde_json::from_value(protocols.mediator.get_config(&atm, &admin).await?)?;
    let mut mediator_config = SharedConfig::new(shared_config)?;
    println!(
        "{}{}{}",
        style("Mediator version(").green(),
        style(&mediator_config.version).color256(208),
        style("). Configuration loaded successfully").green()
    );

    mediator_config.our_admin_hash = digest(admin.dids()?.0);

    loop {
        println!();
        let selections = &["Account Management", "Administration Accounts", "Quit"];

        let selection = Select::with_theme(&theme)
            .with_prompt("Select an action?")
            .default(0)
            .items(&selections[..])
            .interact()
            .unwrap();

        println!();
        match selection {
            0 => {
                account_management_menu(&atm, &admin, &protocols, &theme, &mediator_config).await?;
            }
            1 => {
                administration_accounts_menu(&atm, &admin, &protocols, &theme, &mediator_config)
                    .await;
            }
            2 => {
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

/*0 => {
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
*/
