//! Helps configure the various configuration options, DIDs and keys for the actors in the examples.
//! This helps to create consistency in the examples and also to avoid code duplication.
use affinidi_messaging_helpers::common::{
    affinidi_logo, check_path,
    profiles::{Profiles, PROFILES_PATH},
};
use console::{style, Style, Term};
use dialoguer::{theme::ColorfulTheme, Confirm};
use std::error::Error;
use ui::{init_local_mediator, init_remote_mediator, local_remote_mediator, MediatorType};

mod mediator;
mod network;
mod ssl_certs;
mod ui;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let term = Term::stdout();
    let _ = term.clear_screen();
    affinidi_logo::print_logo();
    // Ensure we are somewhere we should be...
    check_path()?;

    let theme = ColorfulTheme {
        values_style: Style::new().yellow().dim(),
        ..ColorfulTheme::default()
    };

    println!(
        "{}",
        style("Welcome to the Affinidi Messaging setup wizard").green(),
    );

    // Load profiles if they already exist
    let mut profiles = Profiles::load_file(PROFILES_PATH)?;

    // ************ Local or Remote? ************
    let profile_name;
    let type_;
    loop {
        let (t_, profile) = match local_remote_mediator(&theme, &profiles)? { Some(m_t) => {
            match m_t {
                MediatorType::Local => init_local_mediator(&theme, &mut profiles).await?,
                MediatorType::Remote => init_remote_mediator(&theme, &mut profiles).await?,
                MediatorType::Existing(profile) => {
                    (MediatorType::Existing(profile.clone()), Some(profile))
                }
            }
        } _ => {
            println!("{}", style("Exiting...").color256(208));
            return Ok(());
        }};

        if let Some(profile) = profile {
            profile_name = profile;
            type_ = t_;
            break;
        }
    }

    let mut profile = if let Some(profile) = profiles.profiles.get(&profile_name) {
        profile.to_owned()
    } else {
        return Err("Profile not found".into());
    };

    println!();
    println!(
        "  {}{}",
        style("Selected Profile: ").blue(),
        style(&profile_name).color256(208)
    );
    println!();

    // ************ Administration Account ************

    // ************ Friends ************

    if Confirm::with_theme(&theme)
        .with_prompt("You need some friends to run the examples! Would you like to auto-create some friends?")
        .default(true)
        .interact()?
    {
        profile.insert_new_friend( "Alice", profile.default_mediator.clone(), None)?;
        println!("  {}{}", style("Friend Alice created with DID: ").blue(), style(&profile.find_friend("Alice").unwrap().did).color256(208));
        profile.insert_new_friend( "Bob", profile.default_mediator.clone(), None)?;
        println!("  {}{}", style("Friend Bob created with DID: ").blue(), style(&profile.find_friend("Bob").unwrap().did).color256(208));
        profile.insert_new_friend( "Charlie", profile.default_mediator.clone(), None)?;
        println!("  {}{}", style("Friend Charlie created with DID: ").blue(), style(&profile.find_friend("Charlie").unwrap().did).color256(208));
        profile.insert_new_friend( "Malorie", profile.default_mediator.clone(), None)?;
        println!("  {}{}{}{}", style("Friend(?) ").blue(), style("Malorie").red(), style(" created with DID: ").blue(), style(&profile.find_friend("Malorie").unwrap().did).color256(208));
    }

    if Confirm::with_theme(&theme)
        .with_prompt(format!("Save friends to profile: {}?", profile_name))
        .default(true)
        .interact()?
    {
        profiles.add_profile(&profile_name, profile);
        profiles.save()?;
    }

    if type_ == MediatorType::Local {
        println!();
        println!(
            "{}",
            style("You can now run the mediator locally using the following command:").blue()
        );
        println!(
            "  {}",
            style("cd affinidi-messaging-mediator && cargo run").color256(231)
        );
    }

    println!();
    println!(
        "{}",
        style(
            "You can set the environment variable AM_PROFILE to use this profile in the examples."
        )
        .blue()
    );
    println!(
        "  {}",
        style(format!("export AM_PROFILE={}", profile_name)).color256(208)
    );
    println!();
    Ok(())
}
