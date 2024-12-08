use std::collections::HashMap;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use circular_queue::CircularQueue;
use serde::{Deserialize, Serialize};

use super::actions::{
    chat_list::{Chat, ChatList},
    invitation::InvitePopupState,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageBoxItem {
    Message { user_id: String, content: String },
    Notification(String),
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ChatDetailsPopupState {
    pub chat_name: Option<String>,
    pub show: bool,
}

/// Common configuration across all chats
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct CommonSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mediator_did: Option<String>,
    #[serde(skip)]
    pub mediator_did_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_path: Option<String>,
    #[serde(skip)]
    pub avatar_path_error: Option<String>,
    #[serde(skip)]
    pub show_settings_popup: bool,
}

impl CommonSettings {
    async fn _check_mediator_did(
        &self,
        did_resolver: &DIDCacheClient,
    ) -> Result<(), std::io::Error> {
        if let Some(mediator_did) = self.mediator_did.as_ref() {
            if let Err(e) = did_resolver.resolve(mediator_did).await {
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Mediator DID is invalid: {}", e),
                ))
            } else {
                Ok(())
            }
        } else {
            Ok(()) // Empty is fine
        }
    }

    /// Checks if the avatar path is correct
    fn _check_avatar_path(&self) -> Result<(), std::io::Error> {
        if let Some(avatar_path) = self.avatar_path.as_ref() {
            let metadata = std::fs::metadata(avatar_path)?;
            if metadata.is_file() {
                Ok(())
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Avatar path is not a file",
                ))
            }
        } else {
            Ok(())
        }
    }

    /// Checks if the settings are valid
    pub(crate) async fn check(&self, state: &mut State, did_resolver: &DIDCacheClient) -> bool {
        let mut ok_flag = true;
        if let Err(e) = self._check_avatar_path() {
            state.settings.avatar_path_error = Some(e.to_string());
            ok_flag = false;
        } else {
            state.settings.avatar_path_error = None;
        }
        if let Err(e) = self._check_mediator_did(did_resolver).await {
            state.settings.mediator_did_error = Some(e.to_string());
            ok_flag = false;
        } else {
            state.settings.mediator_did_error = None;
        }

        ok_flag
    }

    /// Updates state with the new settings
    pub(crate) async fn update(&self, state: &mut State, did_resolver: &DIDCacheClient) -> bool {
        if self.check(state, did_resolver).await {
            state.settings.mediator_did = self.mediator_did.clone();
            state.settings.avatar_path = self.avatar_path.clone();
            true
        } else {
            false
        }
    }
}

/// State holds the state of the application
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct State {
    pub settings: CommonSettings,
    /// Storage of chat data
    pub chat_list: ChatList,
    #[serde(skip)]
    pub invite_popup: InvitePopupState,
    #[serde(skip)]
    pub chat_details_popup: ChatDetailsPopupState,
}

impl State {
    pub fn save_to_file(&self, file_path: &str) -> Result<(), std::io::Error> {
        let file = std::fs::File::create(file_path)?;
        serde_json::to_writer_pretty(file, self)?;
        Ok(())
    }

    pub fn read_from_file(file_path: &str) -> Result<Self, std::io::Error> {
        let file = std::fs::File::open(file_path)?;
        let state: Self = serde_json::from_reader(file)?;

        Ok(state)
    }
}
