use affinidi_messaging_mediator::common::config::Config;
use affinidi_messaging_sdk::{protocols::Protocols, ATM};
use console::style;
use dialoguer::{theme::ColorfulTheme, Select};

pub(crate) async fn global_acls_menu(
    atm: &mut ATM<'static>,
    protocols: &Protocols,
    theme: &ColorfulTheme,
    mediator_config: &Config,
) {
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
            style(&mediator_config.security.acl_mode).blue()
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
                selected_did = match select_did(theme).await {
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
            }
            2 => {
                return;
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
async fn select_did(theme: &ColorfulTheme) -> Result<Option<String>, Box<dyn std::error::Error>> {
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
        }
        1 => {
            println!("Manually enter DID or DID Hash");
        }
        2 => {
            return Ok(None);
        }
        _ => {
            println!("Invalid selection");
        }
    }

    Ok(None)
}
