/*!
 * Handles ACL management tasks for an account
 */

use affinidi_messaging_sdk::{
    profiles::Profile,
    protocols::{
        mediator::{
            accounts::Account,
            acls::{AccessListModeType, MediatorACLSet},
        },
        Protocols,
    },
    ATM,
};
use console::style;
use dialoguer::{theme::ColorfulTheme, MultiSelect, Select};
use std::sync::Arc;

use crate::SharedConfig;

pub(crate) async fn manage_account_acls(
    atm: &ATM,
    profile: &Arc<Profile>,
    protocols: &Protocols,
    theme: &ColorfulTheme,
    mediator_config: &SharedConfig,
    account: &Account,
) -> Result<Account, Box<dyn std::error::Error>> {
    let selections = &[
        "Modify ACL Flags",
        "Show ACL List",
        "Add to ACL List",
        "Remove from ACL List",
        "Search ACL List",
        "Back",
    ];

    let mut account = account.clone();
    loop {
        println!();
        println!(
            "{} {}  {} {:064b} {} {}",
            style("Selected DID: ").yellow(),
            style(&account.did_hash).color256(208),
            style("ACL:").yellow(),
            style(account.acls).blue().bold(),
            style("Access List Count:").yellow(),
            style(account.access_list_count).blue().bold()
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
                // Modify ACL Flags
                account.acls = _modify_acl_flags(atm, profile, protocols, theme, &account)
                    .await?
                    .to_u64();
            }
            1 => {}
            2 => {}
            3 => {}
            4 => {}
            5 => break,
            _ => println!("Invalid selection"),
        }
    }
    Ok(account)
}

async fn _modify_acl_flags(
    _atm: &ATM,
    _profile: &Arc<Profile>,
    _protocols: &Protocols,
    theme: &ColorfulTheme,
    account: &Account,
) -> Result<MediatorACLSet, Box<dyn std::error::Error>> {
    println!("self-change? : If set, allows the DID to change its own ACL flag");

    let acls = MediatorACLSet::from_u64(account.acls);
    let selections = &[
        (
            "Access List Mode: explicit_deny if set, explicit_allow if not",
            acls.get_access_list_mode().0 == AccessListModeType::ExplicitDeny,
        ),
        (
            "Access List Mode self-change?",
            acls.get_access_list_mode().1,
        ),
        (
            "blocked - DID is blocked from authentication?",
            acls.get_blocked(),
        ),
        (
            "local - DID is able to store messages locally?",
            acls.get_local(),
        ),
        ("send_messages?", acls.get_send_messages().0),
        ("send_messages self-change?", acls.get_send_messages().1),
        ("receive_messages?", acls.get_receive_messages().0),
        (
            "receive_messages self-change?",
            acls.get_receive_messages().1,
        ),
        ("send_forwarded_messages?", acls.get_send_forwarded().0),
        (
            "send_forwarded_messages self-change?",
            acls.get_send_forwarded().1,
        ),
        (
            "receive_forwarded_messages?",
            acls.get_receive_forwarded().0,
        ),
        (
            "receive_forwarded_messages self-change?",
            acls.get_receive_forwarded().1,
        ),
        ("create_invites?", acls.get_create_invites().0),
        ("create_invites self-change?", acls.get_create_invites().1),
        ("anon_receive_messages?", acls.get_anon_receive().0),
        (
            "anon_receive_messages self-change?",
            acls.get_anon_receive().1,
        ),
        ("access_list self-change?", acls.get_self_manage_list()),
    ];

    // returns a vector of chosen indices
    let selection = MultiSelect::with_theme(theme)
        .with_prompt("Select an action? (space to select, enter to confirm)")
        .items_checked(&selections[..])
        .report(false)
        .interact()
        .unwrap();

    // convert the selection to an array of bools
    let mut flags = [false; 17];
    for s in selection {
        flags[s] = true;
    }

    // Create a new ACL set from the values
    let mut new_acls = MediatorACLSet::default();
    let _ = new_acls.set_access_list_mode(
        if flags[0] {
            AccessListModeType::ExplicitDeny
        } else {
            AccessListModeType::ExplicitAllow
        },
        flags[1],
        true,
    );
    new_acls.set_blocked(flags[2]);
    new_acls.set_local(flags[3]);
    let _ = new_acls.set_send_messages(flags[4], flags[5], true);
    let _ = new_acls.set_receive_messages(flags[6], flags[7], true);
    let _ = new_acls.set_send_forwarded(flags[8], flags[9], true);
    let _ = new_acls.set_receive_forwarded(flags[10], flags[11], true);
    let _ = new_acls.set_create_invites(flags[12], flags[13], true);
    let _ = new_acls.set_anon_receive(flags[14], flags[15], true);
    new_acls.set_self_manage_list(flags[16]);

    if new_acls == acls {
        println!("{}", style("No changes made").yellow());
        return Ok(acls);
    }
    println!("New ACLs: {:064b}", new_acls.to_u64());
    todo!("Change the ACL on the mediator");
}
