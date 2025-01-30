use affinidi_messaging_sdk::{
    profiles::Profile,
    protocols::{
        mediator::{
            accounts::{Account, AccountType},
            acls::MediatorACLSet,
        },
        Protocols,
    },
    ATM,
};
use console::style;
use dialoguer::{theme::ColorfulTheme, Input, Select};
use sha256::digest;
use std::sync::Arc;

use crate::{account_management::acl_management::manage_account_acls, SharedConfig};

pub(crate) async fn account_management_menu(
    atm: &ATM,
    profile: &Arc<Profile>,
    protocols: &Protocols,
    theme: &ColorfulTheme,
    mediator_config: &SharedConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let selections = &["Select and Manage Accounts", "Create an Account", "Back"];

    loop {
        println!();
        let selection = Select::with_theme(theme)
            .with_prompt("Select an action?")
            .default(0)
            .items(&selections[..])
            .interact()
            .unwrap();

        match selection {
            0 => {
                select_did(atm, profile, protocols, theme, mediator_config).await?;
            }
            1 => {
                create_account_menu(atm, profile, protocols, theme, mediator_config).await?;
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

pub(crate) async fn create_account_menu(
    atm: &ATM,
    profile: &Arc<Profile>,
    protocols: &Protocols,
    theme: &ColorfulTheme,
    mediator_config: &SharedConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(new_did_hash) = _manually_enter_did_or_hash(theme) else {
        println!("No new account created...");
        return Ok(());
    };

    // Does this account exist?
    if protocols
        .mediator
        .account_get(atm, profile, Some(new_did_hash.clone()))
        .await?
        .is_some()
    {
        println!(
            "{}",
            style("Account already exists on the Mediator").yellow()
        );
        return Ok(());
    }

    // Create the account
    let account = protocols
        .mediator
        .account_add(atm, profile, &new_did_hash, None)
        .await?;

    println!("{}", style("Created account successfully").green());

    manage_account_menu(atm, profile, protocols, theme, mediator_config, &account).await
}

pub(crate) async fn manage_account_menu(
    atm: &ATM,
    profile: &Arc<Profile>,
    protocols: &Protocols,
    theme: &ColorfulTheme,
    mediator_config: &SharedConfig,
    account: &Account,
) -> Result<(), Box<dyn std::error::Error>> {
    let selections = &[
        "Modify ACLs",
        "Change Account Type",
        "Delete Account",
        "Back",
    ];

    let mut account = account.clone();
    loop {
        println!();
        println!(
            "{} {}  {} {:064b}",
            style("Selected DID: ").yellow(),
            style(&account.did_hash).color256(208),
            style("ACL:").yellow(),
            style(account.acls).blue().bold(),
        );

        println!(
            "{} {:<12} {} {} {} {}",
            style("Selected DID Account Type:").yellow(),
            style(&account._type.to_string()).blue().bold(),
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
                // Modify ACLs
                match manage_account_acls(atm, profile, protocols, theme, mediator_config, &account)
                    .await
                {
                    Ok(a) => {
                        account = a;
                    }
                    Err(err) => {
                        println!("{}", style(format!("Error modifying ACLs: {}", err)).red())
                    }
                }
            }
            1 => {
                // Change Account Type
                match _change_account_type(atm, profile, protocols, theme, &account).await {
                    Ok(_type) => {
                        account._type = _type;
                    }
                    Err(err) => println!(
                        "{}",
                        style(format!("Error changing account type: {}", err)).red()
                    ),
                }
            }
            2 => {
                // Delete Account
                match protocols
                    .mediator
                    .account_remove(atm, profile, Some(account.did_hash.clone()))
                    .await
                {
                    Ok(_) => {
                        println!("{}", style("Account deleted successfully").green());
                        return Ok(());
                    }
                    Err(err) => println!(
                        "{}",
                        style(format!("Error deleting account: {}", err)).red()
                    ),
                }
            }
            3 => {
                // Return to previous menu
                return Ok(());
            }
            _ => {
                println!("Invalid selection");
            }
        }
    }
}

async fn _change_account_type(
    atm: &ATM,
    profile: &Arc<Profile>,
    protocols: &Protocols,
    theme: &ColorfulTheme,
    account: &Account,
) -> Result<AccountType, Box<dyn std::error::Error>> {
    let mut selections = AccountType::iterator()
        .map(|t| t.to_string())
        .collect::<Vec<String>>();

    selections.push("Back".to_string());

    let selection = Select::with_theme(theme)
        .with_prompt("Select Account Type?")
        .default(0)
        .items(&selections[..])
        .interact()
        .unwrap();

    if selection == selections.len() - 1 {
        // No change, exit gracefully
        return Ok(account._type);
    }

    let new_type = AccountType::from(selection as u32);
    println!("Changing account type to: {}", new_type);

    if new_type == account._type {
        // No change, exit gracefully
        Ok(account._type)
    } else {
        protocols
            .mediator
            .account_change_type(atm, profile, &account.did_hash, new_type)
            .await
            .map_err(|e| e.to_string())?;
        println!("{}", style("Account type changed successfully").green());
        Ok(new_type)
    }
}

/// Picks the target DID
/// returns the selected DID Hash
/// returns None if the user cancels the selection
pub(crate) async fn select_did(
    atm: &ATM,
    profile: &Arc<Profile>,
    protocols: &Protocols,
    theme: &ColorfulTheme,
    mediator_config: &SharedConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
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

                if let Some(account) = _select_from_existing_dids(
                    atm,
                    profile,
                    protocols,
                    theme,
                    None,
                    mediator_config,
                )
                .await?
                {
                    manage_account_menu(atm, profile, protocols, theme, mediator_config, &account)
                        .await?;
                }
            }
            1 => {
                if let Some(did_hash) = _manually_enter_did_or_hash(theme) {
                    // Look up the Account for this DID
                    let account = protocols
                        .mediator
                        .account_get(atm, profile, Some(did_hash))
                        .await?;
                    if let Some(account) = account {
                        manage_account_menu(
                            atm,
                            profile,
                            protocols,
                            theme,
                            mediator_config,
                            &account,
                        )
                        .await?;
                    }
                }
            }
            2 => return Ok(()),
            _ => {
                println!("Invalid selection");
            }
        }
    }
}

fn _manually_enter_did_or_hash(theme: &ColorfulTheme) -> Option<String> {
    println!();
    println!(
        "{}",
        style("Limited checks are done on the DID or Hash - be careful!").yellow()
    );
    println!("DID or SHA256 Hash of a DID (type exit to quit this dialog)");

    let input: String = Input::with_theme(theme)
        .with_prompt("DID or SHA256 Hash")
        .interact_text()
        .unwrap();

    if input == "exit" {
        return None;
    }

    if input.starts_with("did:") {
        Some(digest(input))
    } else if input.len() != 64 {
        println!(
            "{}",
            style(format!(
                "Invalid SHA256 Hash length. length({}) when expected(64)",
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
    mediator_config: &SharedConfig,
) -> Result<Option<Account>, Box<dyn std::error::Error>> {
    let dids = protocols
        .mediator
        .accounts_list(atm, profile, cursor, Some(2))
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

    did_list.push("Back".to_string());

    println!(
        "  DID SHA-256 Hash                                                 Account Type Blocked? Local? ACL Flags");
    let selected = Select::with_theme(theme)
        .with_prompt("Select DID (space to select, enter to continue)?")
        .items(&did_list)
        .interact()
        .unwrap();

    if selected == did_list.len() - 2 && load_more_flag {
        Box::pin(_select_from_existing_dids(
            atm,
            profile,
            protocols,
            theme,
            Some(dids.cursor),
            mediator_config,
        ))
        .await
    } else if selected == did_list.len() - 1 {
        // Exit gracefully
        Ok(None)
    } else {
        Ok(Some(dids.accounts[selected].clone()))
    }
}
