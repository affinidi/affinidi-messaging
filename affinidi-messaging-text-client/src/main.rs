use std::fs::OpenOptions;

use affinidi_did_resolver_cache_sdk::config::ClientConfigBuilder;
use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use log::LevelFilter;
use state_store::StateStore;
use termination::{create_termination, Interrupted};
use tracing::Level;
use tracing_subscriber::prelude::__tracing_subscriber_SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{filter, fmt, Layer};
use ui_management::UiManager;

mod state_store;
mod termination;
mod ui_management;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let log_file = OpenOptions::new()
        .append(true)
        .create(true)
        .open("log.txt")?;
    tracing_subscriber::registry()
        .with(tui_logger::tracing_subscriber_layer())
        .with(
            fmt::layer()
                .with_ansi(true)
                .with_writer(log_file)
                .with_filter(filter::LevelFilter::from_level(Level::DEBUG)),
        )
        .init();

    tui_logger::init_logger(LevelFilter::Info).unwrap();

    // Setup the initial state
    let did_resolver = DIDCacheClient::new(ClientConfigBuilder::default().build()).await?;

    let (terminator, mut interrupt_rx) = create_termination();
    let (state_store, state_rx) = StateStore::new();
    let (ui_manager, action_rx) = UiManager::new();

    tokio::try_join!(
        state_store.main_loop(
            terminator,
            action_rx,
            interrupt_rx.resubscribe(),
            did_resolver
        ),
        ui_manager.main_loop(state_rx, interrupt_rx.resubscribe()),
    )?;

    match interrupt_rx.recv().await { Ok(reason) => {
        match reason {
            Interrupted::UserInt => println!("exited per user request"),
            Interrupted::OsSigInt => println!("exited because of an os sig int"),
            Interrupted::SystemError => println!("exited because of a system error"),
        }
    } _ => {
        println!("exited because of an unexpected error");
    }}

    Ok(())
}

#[derive(Clone, PartialEq)]
pub enum InputType {
    None,
    MediatorDID,
    AvatarPath,
    OurName,
    ChatMessage,
    AcceptInvite,
    ManualConnectRemoteDID,
    ManualConnectAlias,
}
