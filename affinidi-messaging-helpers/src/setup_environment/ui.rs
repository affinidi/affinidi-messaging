use crate::{
    mediator::{read_config_file, MediatorConfig},
    network::fetch_well_known_did,
    ssl_certs::create_ssl_certs,
};
use affinidi_messaging_helpers::common::{
    did::{create_did, get_service_address},
    profiles::{Profile, Profiles},
};
use console::style;
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Select};
use regex::Regex;
use std::{collections::HashMap, error::Error, path::Path};
use toml::Value;

/// Local or Remote mediator
#[derive(PartialEq)]
pub enum MediatorType {
    Local,
    Remote,
    Existing(String),
}

pub(crate) fn local_remote_mediator(
    theme: &ColorfulTheme,
    profiles: &Profiles,
) -> Result<MediatorType, Box<dyn Error>> {
    println!();

    let mut selections = vec![
        "Local Mediator Configuration".to_string(),
        "Remote Mediator Configuration".to_string(),
    ];
    if !profiles.profiles.is_empty() {
        selections.push("Select Existing Profile?".to_string());
    }

    loop {
        let type_ = Select::with_theme(theme)
            .with_prompt("Configure local or remote mediator?")
            .default(0)
            .items(&selections[..])
            .interact()?;

        match type_ {
            0 => return Ok(MediatorType::Local),
            1 => return Ok(MediatorType::Remote),
            2 => {
                if profiles.profiles.is_empty() {
                    unreachable!("No profiles to manage");
                } else if let Some(profile) = select_profile(theme, profiles)? {
                    return Ok(profile);
                }
            }
            _ => unreachable!(),
        }
    }
}

fn select_profile(
    theme: &ColorfulTheme,
    profiles: &Profiles,
) -> Result<Option<MediatorType>, Box<dyn Error>> {
    let mut selections: Vec<&String> = profiles.profiles.keys().collect();

    let main_menu = "Back to Main Menu".to_string();
    selections.push(&main_menu);

    let profile = Select::with_theme(theme)
        .with_prompt("Select Profile")
        .default(0)
        .items(&selections[..])
        .interact()?;

    if profile == selections.len() - 1 {
        // Go back to the previous menu
        Ok(None)
    } else {
        Ok(Some(MediatorType::Existing(
            selections[profile].to_string(),
        )))
    }
}

/// Gets a profile name and saves the profile
fn save_profile(
    theme: &ColorfulTheme,
    profiles: &mut Profiles,
    profile: Profile,
    name: &str,
) -> Result<Option<String>, Box<dyn Error>> {
    println!();
    if let Ok(name) = Input::<String>::with_theme(theme)
        .with_prompt("Save profile with name?")
        .with_initial_text(name)
        .interact_text()
    {
        if Confirm::with_theme(theme)
            .with_prompt(format!("Save Profile: {}?", name))
            .default(true)
            .interact()?
        {
            if profiles.add(&name, profile) {
                println!("  {}", style("Profile added").green());
            } else {
                println!("  {}", style("Profile replaced").color256(208));
            }

            profiles.save()?;
            println!("  {}", style("Profiles saved...").green());
            Ok(Some(name))
        } else {
            println!("  {}", style("Profile not saved").red());
            Ok(None)
        }
    } else {
        Err("Profile name not provided".into())
    }
}

/// Initialize remote mediator configuration
/// Expected that the remote mediator is already up and running
pub(crate) async fn init_remote_mediator(
    theme: &ColorfulTheme,
    profiles: &mut Profiles,
) -> Result<(MediatorType, Option<String>), Box<dyn Error>> {
    fn _ask_for_remote_address(theme: &ColorfulTheme) -> Result<String, Box<dyn Error>> {
        let address = Input::with_theme(theme)
            .with_prompt("Remote Mediator Address")
            .default("https://localhost:7037/msg/v1/mediator".to_string())
            .interact_text()?;

        Ok(address)
    }

    fn _ask_for_remote_did(theme: &ColorfulTheme) -> Result<String, Box<dyn Error>> {
        let did = Input::with_theme(theme)
            .with_prompt("Remote Mediator DID")
            .report(false)
            .interact()?;

        Ok(did)
    }

    fn _ssl_cert(theme: &ColorfulTheme) -> Result<Option<String>, Box<dyn Error>> {
        if Confirm::with_theme(theme)
            .with_prompt("Do you need to provide an SSL certificate?")
            .interact()?
        {
            loop {
                let cert = Input::with_theme(theme)
                    .with_prompt("SSL Certificate Path")
                    .interact_text()?;

                if Path::new(&cert).exists() {
                    println!("  {}", style("SSL Certificate exists").green());
                    return Ok(Some(cert));
                } else {
                    println!("  {}", style("File does not exist!").red());
                }
            }
        } else {
            Ok(None)
        }
    }

    let mediator_did;
    let mut network_address;

    if !Confirm::with_theme(theme)
        .with_prompt("The remote mediator must be already running. Continue?")
        .default(true)
        .interact()?
    {
        return Err("Remote Mediator must be running!".into());
    }

    if Confirm::with_theme(theme)
        .with_prompt("Do you know the DID of the remote Mediator?")
        .default(true)
        .interact()?
    {
        mediator_did = _ask_for_remote_did(theme)?;
        // extract the remote address from the did
        network_address = get_service_address(&mediator_did).await?;
        println!(
            "  {}{}",
            style("Mediator address from DID: ").green(),
            style(&network_address).color256(208)
        );
        if !Confirm::with_theme(theme)
            .with_prompt("Do you want to use this mediator address?")
            .default(true)
            .interact()?
        {
            network_address = _ask_for_remote_address(theme)?;
        }

        println!(
            "  {}",
            style("Checking if the mediator is reachable...").yellow()
        );
        let well_known_did = fetch_well_known_did(&network_address).await?;
        if well_known_did != mediator_did {
            println!(
                " {}",
                style("Mediator well-known DID does not match the provided DID!").red()
            );
            return Err("Well-known DID does not match the provided DID".into());
        }
        println!(
            " {}",
            style("Mediator is reachable and DID/address match...").green()
        );
    } else {
        network_address = _ask_for_remote_address(theme)?;
        // Connect to the mediator and get the well-known DID
        mediator_did = fetch_well_known_did(&network_address).await?;
        println!(
            "  {}{}",
            style("Well-known DID fetched successfully: ").green(),
            style(&mediator_did).color256(208)
        );
    }

    // We need to know where the SSL Certificate is if needed?
    let ssl_certificate = _ssl_cert(theme)?;
    let profile = Profile {
        mediator_did,
        network_address,
        ssl_certificate,
        friends: HashMap::new(),
    };

    Ok((
        MediatorType::Remote,
        save_profile(theme, profiles, profile, "remote")?,
    ))
}

/// Initialize local mediator configuration
pub(crate) async fn init_local_mediator(
    theme: &ColorfulTheme,
    profiles: &mut Profiles,
) -> Result<(MediatorType, Option<String>), Box<dyn Error>> {
    /// Rewrite the network address from listen address to localhost
    /// - config: Mediator Configuration
    fn _rewrite_network_address(config: &Value) -> Result<String, Box<dyn Error>> {
        // example: listen address = "0.0.0.0:7037"
        let re = Regex::new(r"[^:]*:?(\d*)?").unwrap();

        let server_block = if let Some(server) = config.get("server") {
            server
        } else {
            return Err("Could not find server configuration block".into());
        };

        let listen_address = if let Some(listen_address) = server_block.get("listen_address") {
            if let Some(listen_address) = listen_address.as_str() {
                listen_address
            } else {
                return Err("server.listen_address isn't a string".into());
            }
        } else {
            return Err("Could not find listen_address in server configuration block".into());
        };

        if let Some(groups) = re.captures(listen_address) {
            if groups.len() == 2 {
                if let Some(api_prefix) = server_block.get("api_prefix") {
                    if let Some(api_prefix) = api_prefix.as_str() {
                        return Ok(format!("https://localhost:{}{}", &groups[1], api_prefix));
                    }
                }
            }
        }
        Err("Could not determine network address from mediator configuration".into())
    }

    // Handles picking the mediator address from the configuration or create a new one
    fn _mediator_address(
        config: &Value,
        new_config: &mut MediatorConfig,
        theme: &ColorfulTheme,
    ) -> Result<(), Box<dyn Error>> {
        if let Some(mediator_did) = config.get("mediator_did") {
            if let Some(mediator_did) = mediator_did.as_str() {
                let mediator_did = if let Some(mediator_did) = mediator_did.strip_prefix("did://") {
                    mediator_did
                } else {
                    mediator_did
                };

                println!(
                    "  {}{}",
                    style("Mediator DID: ").blue(),
                    style(mediator_did).color256(208)
                );
                if Confirm::with_theme(theme)
                    .with_prompt("Use existing Mediator DID?")
                    .default(true)
                    .interact()?
                {
                    new_config.mediator_did = Some(mediator_did.to_string());
                    println!("  {}", style("You will need to ensure that the secrets for the Mediator DID are saved as well!!!").cyan());
                    return Ok(());
                }
            }
        }

        let response = create_did(Some("https://localhost:7037/".into()))?;
        new_config.mediator_did = Some(response.0.clone());
        new_config.mediator_secrets = Some(response.1);
        println!(
            "  {} {}",
            style("Mediator DID created: ").blue().bold(),
            style(&response.0).color256(208)
        );

        Ok(())
    }

    // Setup the initial mediator configuration
    println!();
    let mut new_mediator_config = MediatorConfig::default();
    let mediator_config = read_config_file("affinidi-messaging-mediator/conf/mediator.toml")?;

    println!("Configuring local mediator...");

    _mediator_address(&mediator_config, &mut new_mediator_config, theme)?;

    println!();
    if Confirm::with_theme(theme)
        .with_prompt("Create new JWT authorization secrets?")
        .default(true)
        .interact()?
    {
        new_mediator_config.create_jwt_secrets()?;
    }

    println!();
    if Confirm::with_theme(theme)
        .with_prompt("Save mediator configuration?")
        .default(true)
        .interact()?
    {
        new_mediator_config.save_config()?;
    }

    println!();
    if Confirm::with_theme(theme)
        .with_prompt("Create local SSL certificates and root authority for testing/development?")
        .default(true)
        .interact()?
    {
        create_ssl_certs()?;
        println!(
            "  {}{}{}",
            style("SSL certificates etc saved to (").blue(),
            style("./affinidi-messaging-mediator/conf/keys/").color256(201),
            style(")").blue()
        );
    }

    let profile = Profile {
        mediator_did: new_mediator_config.mediator_did.clone().unwrap(),
        network_address: _rewrite_network_address(&mediator_config)?,
        ssl_certificate: Some("./affinidi-messaging-mediator/conf/keys/client.cert".to_string()),
        friends: HashMap::new(),
    };
    Ok((
        MediatorType::Local,
        save_profile(theme, profiles, profile, "local")?,
    ))
}
