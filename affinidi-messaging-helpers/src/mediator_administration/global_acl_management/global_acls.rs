use std::sync::Arc;

use affinidi_messaging_sdk::{profiles::Profile, protocols::Protocols, ATM};
use console::style;
use dialoguer::{theme::ColorfulTheme, Input, Select};
use sha256::digest;

use crate::BasicMediatorConfig;

pub(crate) async fn global_acls_menu(
    atm: &ATM,
    profile: &Arc<Profile>,
    protocols: &Protocols,
    theme: &ColorfulTheme,
    mediator_config: &BasicMediatorConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let selections = &["Select and Set Active DID", "Set ACLs", "Back"];

    let mut selected_did: Option<String> = None;
    loop {
        println!();
        print!("{}", style("Currently selected DID: ").yellow());
        if let Some(did) = &selected_did {
            println!("{}", style(did).blue());
        } else {
            println!("{}", style("None").red());
        }

        println!(
            "{}{}",
            style("Mediator ACL Mode: ").yellow(),
            style(&mediator_config.acl_mode).blue()
        );

        println!();
        let selection = Select::with_theme(theme)
            .with_prompt("Select an action?")
            .default(0)
            .items(&selections[..])
            .interact()
            .unwrap();

        match selection {
            0 => {
                selected_did = match select_did(atm, profile, protocols, theme).await {
                    Ok(did) => {
                        if let Some(did) = did {
                            Some(did)
                        } else {
                            // No DID was selected
                            selected_did
                        }
                    }
                    Err(e) => {
                        println!("{}", style(format!("Error: {}", e)).red());
                        None
                    }
                }
            }
            1 => {
                println!("Set ACLs");
                let r = protocols
                    .mediator
                    .global_acls_get(atm, profile, &vec![selected_did.clone().unwrap()])
                    .await?;
                println!("{:#?}", r);
            }
            2 => {
                return Ok(());
            }
            _ => {
                println!("Invalid selection");
            }
        }
    }
}

/// Picks the target DID
/// returns the selected DID Hash
/// returns None if the user cancels the selection
async fn select_did(
    atm: &ATM,
    profile: &Arc<Profile>,
    protocols: &Protocols,
    theme: &ColorfulTheme,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let selection = Select::with_theme(theme)
        .with_prompt("Select an action?")
        .default(0)
        .items(&[
            "Scan existing DIDs on Mediator?",
            "Manually enter DID or DID Hash?",
            "Back",
        ])
        .interact()
        .unwrap();

    match selection {
        0 => {
            println!("Scan existing DIDs on Mediator");

            Ok(_select_from_existing_dids(atm, profile, protocols, theme, None).await?)
        }
        1 => Ok(_manually_enter_did_or_hash(theme)),
        2 => Ok(None),
        _ => {
            println!("Invalid selection");
            Ok(None)
        }
    }
}

fn _manually_enter_did_or_hash(theme: &ColorfulTheme) -> Option<String> {
    println!();
    println!(
        "{}",
        style("Limited checks are done on the DID or Hash - be careful!").yellow()
    );
    println!("DID or SHA256 Hash of a DID to work with? (type exit to quit this dialog)");

    let input: String = Input::with_theme(theme)
        .with_prompt("DID or SHA256 Hash")
        .interact_text()
        .unwrap();

    if input == "exit" {
        return None;
    }

    if input.starts_with("did:") {
        Some(digest(input))
    } else if input.len() != 32 {
        println!(
            "{}",
            style(format!(
                "Invalid SHA256 Hash length. length({}) when expected(32)",
                input.len()
            ))
            .red()
        );
        None
    } else {
        Some(input.to_ascii_lowercase())
    }
}

async fn _select_from_existing_dids(
    atm: &ATM,
    profile: &Arc<Profile>,
    protocols: &Protocols,
    theme: &ColorfulTheme,
    cursor: Option<u32>,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let dids = protocols
        .mediator
        .list_accounts(atm, profile, cursor, Some(2))
        .await?;

    if dids.accounts.is_empty() {
        println!("{}", style("No DIDs found").red());
        println!();
        return Ok(None);
    }

    let mut did_list = dids.accounts.to_vec();
    let mut load_more_flag = false;
    if dids.cursor > 0 {
        did_list.push("Load more DIDs...".to_string());
        load_more_flag = true;
    }

    let selected = Select::with_theme(theme)
        .with_prompt("Select DID (space to select, enter to continue)?")
        .items(&did_list)
        .report(false)
        .interact()
        .unwrap();

    if selected == did_list.len() - 1 && load_more_flag {
        Box::pin(_select_from_existing_dids(
            atm,
            profile,
            protocols,
            theme,
            Some(dids.cursor),
        ))
        .await
    } else {
        Ok(Some(did_list[selected].clone()))
    }
}
