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
                println!("Select DID");
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
