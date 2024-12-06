use super::{actions::Action, State};
use crate::{
    state_store::actions::invitation::create_invitation,
    termination::{Interrupted, Terminator},
};
use affinidi_did_resolver_cache_sdk::{config::ClientConfigBuilder, DIDCacheClient};
use affinidi_messaging_sdk::{config::ConfigBuilder, ATM};
use std::time::Duration;
use tokio::sync::{
    broadcast,
    mpsc::{self, UnboundedReceiver, UnboundedSender},
};
use tracing::warn;

pub struct StateStore {
    state_tx: UnboundedSender<State>,
}

impl StateStore {
    pub fn new() -> (Self, UnboundedReceiver<State>) {
        let (state_tx, state_rx) = mpsc::unbounded_channel::<State>();

        (StateStore { state_tx }, state_rx)
    }
}

impl StateStore {
    pub async fn main_loop(
        self,
        mut terminator: Terminator,
        mut action_rx: UnboundedReceiver<Action>,
        mut interrupt_rx: broadcast::Receiver<Interrupted>,
    ) -> anyhow::Result<Interrupted> {
        // Setup the initial state
        let did_resolver = DIDCacheClient::new(ClientConfigBuilder::default().build()).await?;

        let atm = match ATM::new(
            ConfigBuilder::default()
                .with_external_did_resolver(&did_resolver)
                .build()?,
        )
        .await
        {
            Ok(atm) => atm,
            Err(e) => {
                warn!("Failed to initialize ATM: {}", e);
                return Ok(Interrupted::SystemError);
            }
        };

        let mut state = State::read_from_file("config.json").unwrap_or_default();
        // Send the initial state once
        self.state_tx.send(state.clone())?;

        let mut ticker = tokio::time::interval(Duration::from_secs(1));

        let result = loop {
            tokio::select! {
                // Handle the server events as they come in
                /*maybe_event = event_stream.next() => match maybe_event {
                    Some(Ok(event)) => {
                        state.handle_server_event(&event);
                    },
                    // server disconnected, we need to reset the state
                    None => {
                        opt_server_handle = None;
                        state = State::default();
                    },
                    _ => (),
                },
                */
                // Handle the actions coming from the UI
                // and process them to do async operations
                Some(action) = action_rx.recv() => match action {
                    Action::SendMessage { content } => {
                        // TODO: send the message
                        warn!("Sending message: {}", content);
                    },
                    Action::SelectChat { chat } => {
                        state.try_set_active_chat(chat.as_str());
                    },
                    Action::Exit => {
                        let _ = terminator.terminate(Interrupted::UserInt);

                        break Interrupted::UserInt;
                    },
                    Action::SettingsPopupToggle => {
                        state.settings.show_settings_popup = !state.settings.show_settings_popup;
                    },
                    Action::SettingsCheck { settings } => {
                        settings.check(&mut state, &did_resolver).await;
                    }
                    Action::SettingsUpdate { settings } => {
                        if settings.update(&mut state, &did_resolver).await {
                            state.settings.show_settings_popup = false;
                        }
                    }
                    Action::InvitePopupStart => {
                        let _ = create_invitation(&mut state, &self.state_tx, &atm).await;
                    },
                    Action::InvitePopupStop => {
                        state.invite_popup.show_invite_popup = false;
                        state.invite_popup.invite = None;
                    },
                },
                // Tick to terminate the select every N milliseconds
                _ = ticker.tick() => {
                    // Do nothing
                },
                // Catch and handle interrupt signal to gracefully shutdown
                Ok(interrupted) = interrupt_rx.recv() => {
                    break interrupted;
                }
            }
            self.state_tx.send(state.clone())?;
        };

        let _ = state.save_to_file("config.json");

        Ok(result)
    }
}
