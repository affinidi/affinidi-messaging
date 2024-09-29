//! Helps configure the various configuration options, DIDs and keys for the actors in the examples.
//! This helps to create consistency in the examples and also to avoid code duplication.
use console::{style, Style, Term};
use dialoguer::{theme::ColorfulTheme, Confirm};
use mediator::MediatorConfig;
use ssl_certs::create_ssl_certs;
use std::{env, error::Error};

mod affinidi_logo;
mod mediator;
mod ssl_certs;

/// Ensures we are running this example from the root of the affinidi-messaging repository
fn check_paths() -> bool {
    if !env::current_dir().unwrap().ends_with("affinidi-messaging") {
        println!(
            "{}",
            style("Please run this script from the root of the affinidi-messaging repository")
                .red()
        );
        return false;
    }
    true
}

/// Initialize local mediator configuration
fn init_local_mediator(theme: &ColorfulTheme) -> Result<Option<MediatorConfig>, Box<dyn Error>> {
    let mut mediator_config = MediatorConfig::default();

    if !Confirm::with_theme(theme)
        .with_prompt("Do you want to configure local mediator?")
        .interact()?
    {
        return Ok(None);
    }

    println!("Configuring local mediator...");

    if Confirm::with_theme(theme)
        .with_prompt("Do you want to create a new DID for the mediator DID?")
        .interact()?
    {
        let response = mediator_config.create_did(true)?;
        mediator_config.mediator_did = Some(response.0.clone());
        mediator_config.mediator_secrets = Some(response.1);
        println!(
            "  {} {}",
            style("Mediator DID created: ").blue().bold(),
            style(&response.0).color256(208)
        );
    }

    if Confirm::with_theme(theme)
        .with_prompt("Do you want to create a new administration DID and secrets?")
        .interact()?
    {
        let response = mediator_config.create_did(false)?;
        mediator_config.admin_did = Some(response.0.clone());
        mediator_config.admin_secrets = Some(response.1);
        println!(
            "  {} {}",
            style("Administration DID created: ").blue().bold(),
            style(&response.0).color256(208)
        );
    }

    if Confirm::with_theme(theme)
        .with_prompt("Save mediator configuration?")
        .interact()?
    {
        mediator_config.save_config()?;
    }

    Ok(Some(mediator_config))
}

fn main() -> Result<(), Box<dyn Error>> {
    let term = Term::stdout();
    let _ = term.clear_screen();
    affinidi_logo::print_logo();

    // Check if we are in the right directory
    if !check_paths() {
        println!(
            "{}",
            style("ERROR: repository doesn't look right. Please check out the affinidi_messaging repository and run this script from the top level directory.")
                .red()
        );
        return Err("Repository not found".into());
    }

    let theme = ColorfulTheme {
        values_style: Style::new().yellow().dim(),
        ..ColorfulTheme::default()
    };

    println!(
        "{}",
        style("Welcome to the Affinidi Messaging setup wizard").green(),
    );

    println!();
    init_local_mediator(&theme)?;

    println!();
    if Confirm::with_theme(&theme)
        .with_prompt("Create local SSL certificates and root authority for testing/development?")
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

    println!();
    Ok(())
}
