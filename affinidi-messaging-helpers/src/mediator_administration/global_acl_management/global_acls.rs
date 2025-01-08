use std::sync::Arc;

use affinidi_messaging_sdk::{
    profiles::Profile,
    protocols::{mediator::acls::MediatorACLSet, Protocols},
    ATM,
};
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
            "{} {}\t{} {}",
            style("Mediator ACL Mode:").yellow(),
            style(&mediator_config.acl_mode).blue().bold(),
            style("Default ACL:").yellow(),
            style(format!(
                "{:064b}",
                &mediator_config.global_acl_default.to_u64()
            ))
            .blue()
            .bold()
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
                selected_did =
                    match select_did(atm, profile, protocols, theme, mediator_config).await {
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
    mediator_config: &BasicMediatorConfig,
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

            Ok(
                _select_from_existing_dids(atm, profile, protocols, theme, None, mediator_config)
                    .await?,
            )
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
    mediator_config: &BasicMediatorConfig,
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

    let mut did_list: Vec<String> = Vec::new();
    for account in &dids.accounts {
        let acls = MediatorACLSet::from_u64(account.acls);
        let acl_default_flag = account.acls == mediator_config.global_acl_default.to_u64();

        did_list.push(format!(
            "{} {} {:^8} {:^6} {:064b} {}",
            account.did_hash,
            style(format!("{:^12}", account._type.to_string())).blue(),
            if acls.get_blocked() {
                style("Yes").red().bold()
            } else {
                style("No").green()
            },
            if acls.get_local() {
                style("Yes").green().bold()
            } else {
                style("No").red()
            },
            if acl_default_flag {
                style(account.acls).green()
            } else {
                style(account.acls).cyan()
            },
            if acl_default_flag {
                style("Default").green()
            } else {
                style("Custom").cyan()
            }
        ));
    }
    let mut load_more_flag = false;
    if dids.cursor > 0 {
        did_list.push("Load more DIDs...".to_string());
        load_more_flag = true;
    }

    println!(
        "  DID SHA-256 Hash                                                 Account Type Blocked? Local? ACL Flags");
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
            mediator_config,
        ))
        .await
    } else {
        Ok(Some(dids.accounts[selected].did_hash.clone()))
    }
}
