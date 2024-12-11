use super::{actions::Action, State};
use crate::{
    state_store::{
        actions::invitation::create_invitation, inbound_messages::handle_message,
        outbound_messages::send_message,
    },
    termination::{Interrupted, Terminator},
};
use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_messaging_sdk::{
    config::ConfigBuilder, transports::websockets::ws_handler::WsHandlerMode, ATM,
};
use std::time::Duration;
use tokio::sync::{
    broadcast,
    mpsc::{self, UnboundedReceiver, UnboundedSender},
};
use tracing::{info, warn};

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
        did_resolver: DIDCacheClient,
    ) -> anyhow::Result<Interrupted> {
        // Setup the initial state
        let atm = match ATM::new(
            ConfigBuilder::default()
                .with_external_did_resolver(&did_resolver)
                .with_ws_handler_mode(WsHandlerMode::DirectChannel)
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

        // Load any profiles from existing chats.
        let mut state = State::read_from_file("config.json").unwrap_or_default();

        if !state.chat_list.chats.is_empty() {
            // Set the first chat as the active chat
            state.chat_list.active_chat = state.chat_list.chats.keys().next().cloned();
        }

        // Send the initial state once
        self.state_tx.send(state.clone())?;

        info!("Activating ({}) profiles", state.chat_list.chats.len());
        for chat in state.chat_list.chats.values() {
            let profile = match chat.our_profile.into_profile(&atm).await {
                Ok(profile) => profile,
                Err(e) => {
                    warn!("Failed to load profile for chat {}: {}", chat.name, e);
                    return Ok(Interrupted::SystemError);
                }
            };

            match atm.profile_add(&profile, true).await {
                Ok(_) => info!(
                    "Profile ({}) added for chat {}",
                    profile.inner.alias, chat.name
                ),
                Err(e) => {
                    warn!("Failed to add profile for chat {}: {}", chat.name, e);
                    return Ok(Interrupted::SystemError);
                }
            }
        }

        let mut inbound_message_channel = if let Some(channel) = atm.get_inbound_channel() {
            channel
        } else {
            warn!("Failed to get inbound channel");
            return Ok(Interrupted::SystemError);
        };

        let mut ticker = tokio::time::interval(Duration::from_secs(1));

        let result = loop {
            tokio::select! {
                message_received = inbound_message_channel.recv() => {
                    match message_received {
                        Ok((message, _)) => {
                            handle_message(&atm, &mut state, &message).await;
                        },
                        Err(e) => {
                            warn!("Failed to receive message: {}", e);
                        }
                    }
                    //handle_message(&atm, &mut state, message, meta);
                },
                Some(action) = action_rx.recv() => match action {
                    Action::SendMessage { chat_msg } => {
                       send_message(&mut state, &atm, &chat_msg).await;
                    },
                    Action::DeleteChat { chat } => {
                        match state.chat_list.chats.remove(&chat) {
                            Some(_) => {
                                info!("Chat {} removed", chat);
                            },
                            None => {
                                warn!("Chat {} not found", chat);
                            }
                        }
                        let _ = atm.profile_remove(&chat).await;
                        state.chat_list.active_chat = state.chat_list.chats.keys().next().cloned();
                    },
                    Action::ShowChatDetails { chat} => {
                        state.chat_details_popup.show = true;
                        state.chat_details_popup.chat_name = Some(chat.clone());
                    },
                    Action::CloseChatDetails => {
                        state.chat_details_popup.show = false;
                        state.chat_details_popup.chat_name = None;
                    },
                    Action::SetCurrentChat { chat } => {
                        state.chat_list.active_chat = Some(chat.clone());
                        if let Some(chat) = state.chat_list.chats.get_mut(&chat) {
                            chat.has_unread = false;
                        }
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
                        info!("OOB Invitation created and added to Chats");
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
