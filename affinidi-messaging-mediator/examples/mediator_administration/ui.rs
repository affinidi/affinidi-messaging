//! UI Related functions
use std::error::Error;

use affinidi_messaging_sdk::{protocols::Protocols, ATM};
use console::style;
use dialoguer::{theme::ColorfulTheme, Confirm, Input, MultiSelect, Select};
use regex::Regex;
use sha256::digest;

/// Returns the path to the mediator directory depending on where you are
pub fn check_path() -> Result<String, Box<dyn Error>> {
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

pub(crate) fn main_menu(theme: &ColorfulTheme) -> usize {
    let selections = &[
        "List Administration DIDs",
        "Add new Administration DID",
        "Remove Administration DID",
        "Global ACL Management",
        "Quit",
    ];

    Select::with_theme(theme)
        .with_prompt("Select an action?")
        .default(0)
        .items(&selections[..])
        .interact()
        .unwrap()
}

/// List first 100 Administration DIDs
pub(crate) async fn list_admins(
    atm: &mut ATM<'static>,
    protocols: &Protocols,
    root_admin_hash: &str,
) {
    match protocols.mediator.list_admins(atm, None, None).await {
        Ok(admins) => {
            println!(
                "{}",
                style("Listing Administration DIDs (SHA256 Hashed DID's). NOTE: Will only list first 100 admin accounts!").green()
            );

            for (idx, admin) in admins.admins.iter().enumerate() {
                print!("  {}", style(format!("{}: {}", idx, admin)).yellow());
                if admin == root_admin_hash {
                    println!(" {}", style(" mediator_root").red());
                } else {
                    println!();
                }
            }
        }
        Err(e) => {
            println!("{}", style(format!("Error: {}", e)).red());
        }
    }
}

/// Add new Administration DID
pub(crate) async fn add_admin(
    atm: &mut ATM<'static>,
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
        match protocols.mediator.add_admins(atm, &[input.clone()]).await {
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
    atm: &mut ATM<'static>,
    protocols: &Protocols,
    root_admin_hash: &String,
    theme: &ColorfulTheme,
) {
    match protocols.mediator.list_admins(atm, None, None).await {
        Ok(admins) => {
            // remove the mediator administrator account from the list
            let admins: Vec<&String> = admins
                .admins
                .iter()
                .filter(|&x| x != root_admin_hash)
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

            println!();
            println!("{}", style("Removing the following DIDs:").green());
            for did in &dids {
                println!("  {}", style(admins[did.to_owned()]).yellow());
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
                match protocols.mediator.remove_admins(atm, &admins).await {
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
