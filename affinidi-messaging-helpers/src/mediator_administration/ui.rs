//! UI Related functions
use affinidi_messaging_sdk::{
    profiles::Profile,
    protocols::{mediator::accounts::AccountType, Protocols},
    ATM,
};
use console::style;
use dialoguer::{theme::ColorfulTheme, Confirm, Input, MultiSelect, Select};
use regex::Regex;
use sha256::digest;
use std::sync::Arc;

use crate::SharedConfig;

pub(crate) async fn administration_accounts_menu(
    atm: &ATM,
    profile: &Arc<Profile>,
    protocols: &Protocols,
    theme: &ColorfulTheme,
    shared_config: &SharedConfig,
) {
    let selections = &[
        "List Administration DIDs",
        "Add Administration rights to a DID (will create if it doesn't exist)",
        "Strip Administration rights from a DID (DID will be set back to Standard)",
        "Back",
    ];

    loop {
        let selection = Select::with_theme(theme)
            .with_prompt("Select an action?")
            .default(0)
            .items(&selections[..])
            .interact()
            .unwrap();

        match selection {
            0 => {
                list_admins(atm, profile, protocols, shared_config).await;
            }
            1 => add_admin(atm, profile, protocols, theme).await,
            2 => remove_admins(atm, profile, protocols, shared_config, theme).await,
            3 => {
                break;
            }
            _ => {
                println!("Invalid selection");
            }
        }
    }
}

/// List first 100 Administration DIDs
pub(crate) async fn list_admins(
    atm: &ATM,
    profile: &Arc<Profile>,
    protocols: &Protocols,
    config: &SharedConfig,
) {
    match protocols
        .mediator
        .list_admins(atm, profile, None, None)
        .await
    {
        Ok(admins) => {
            println!(
                "{}",
                style("Listing Administration DIDs (SHA256 Hashed DID's). NOTE: Will only list first 100 admin accounts!").green()
            );

            for (idx, admin) in admins.accounts.iter().enumerate() {
                print!(
                    "  {}",
                    style(format!("{}: {}", idx, admin.did_hash)).yellow(),
                );
                let (role, color) = match admin._type {
                    AccountType::Mediator => (admin._type.to_string(), 27_u8),
                    AccountType::RootAdmin => (admin._type.to_string(), 127_u8),
                    AccountType::Admin => (admin._type.to_string(), 129_u8),
                    _ => ("Unknown".into(), 1_u8),
                };
                print!(" {}", style(format!("({})", role)).color256(color));
                if admin.did_hash == config.our_admin_hash {
                    print!(" {}", style("(our Admin account)").color256(208));
                }

                println!();
            }
        }
        Err(e) => {
            println!("{}", style(format!("Error: {}", e)).red());
        }
    }
}

/// Add new Administration DID
pub(crate) async fn add_admin(
    atm: &ATM,
    profile: &Arc<Profile>,
    protocols: &Protocols,
    theme: &ColorfulTheme,
) {
    println!("Adding new Administration DID (type exit to quit this dialog)");

    let input: String = Input::with_theme(theme)
        .with_prompt("DID to add")
        .validate_with(|input: &String| -> Result<(), &str> {
            let re = Regex::new(r"did:\w*:\w*").unwrap();
            if re.is_match(input) || input == "exit" {
                Ok(())
            } else {
                Err("Invalid DID format")
            }
        })
        .interact_text()
        .unwrap();

    if input == "exit" {
        return;
    }

    if Confirm::with_theme(theme)
        .with_prompt(format!("Do you want to add DID ({})?", &input))
        .interact()
        .unwrap()
    {
        match protocols
            .mediator
            .add_admins(atm, profile, &[input.clone()])
            .await
        {
            Ok(result) => {
                if result == 1 {
                    println!(
                        "{}",
                        style(format!("Successfully added DID ({})", &input)).green()
                    );
                    println!(
                        "  {}{}",
                        style("DID Hash: ").green(),
                        style(digest(&input)).yellow()
                    );
                } else {
                    println!(
                        "{}",
                        style(format!("DID ({}) already exists", &input)).color256(208)
                    );
                }
            }
            Err(e) => {
                println!("{}", style(format!("Error: {}", e)).red());
            }
        }
    }
}

pub(crate) async fn remove_admins(
    atm: &ATM,
    profile: &Arc<Profile>,
    protocols: &Protocols,
    config: &SharedConfig,
    theme: &ColorfulTheme,
) {
    match protocols
        .mediator
        .list_admins(atm, profile, None, None)
        .await
    {
        Ok(admins) => {
            // remove the mediator administrator account from the list
            let admins: Vec<String> = admins
                .accounts
                .iter()
                .filter_map(|x| {
                    if x.did_hash != config.our_admin_hash && x.did_hash != config.mediator_did_hash
                    {
                        Some(x.did_hash.clone())
                    } else {
                        None
                    }
                })
                .collect();

            if admins.is_empty() {
                println!("{}", style("No Admin DIDs can be removed").red());
                println!();
                return;
            }
            let dids = MultiSelect::with_theme(theme)
                .with_prompt("Select DIDs to remove (space to select, enter to continue)?")
                .items(&admins)
                .report(false)
                .interact()
                .unwrap();

            if dids.is_empty() {
                println!("{}", style("No Admin DIDs selected").red());
                return;
            }

            println!();
            println!("{}", style("Removing the following DIDs:").green());
            for did in &dids {
                println!("  {}", style(&admins[did.to_owned()]).yellow());
            }

            if Confirm::with_theme(theme)
                .with_prompt("Do you want to remove the selected DIDs?")
                .interact()
                .unwrap()
            {
                let admins = dids
                    .iter()
                    .map(|&idx| admins[idx].clone())
                    .collect::<Vec<_>>();
                match protocols.mediator.strip_admins(atm, profile, &admins).await {
                    Ok(result) => {
                        println!("{}", style(format!("Removed {} DIDs", result)).green());
                    }
                    Err(e) => {
                        println!("{}", style(format!("Error: {}", e)).red());
                    }
                }
            }
        }
        Err(e) => {
            println!("{}", style(format!("Error: {}", e)).red());
        }
    }
}
