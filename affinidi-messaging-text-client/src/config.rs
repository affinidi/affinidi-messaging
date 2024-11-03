use affinidi_messaging_sdk::secrets::Secret;
use ratatui_image::protocol::StatefulProtocol;
use serde::{Deserialize, Serialize};

use crate::messages::Message;

#[derive(Default, Serialize, Deserialize)]
pub(crate) struct ClientConfig {
    pub mediator_did: String,
    pub our_avatar_path: String, // path to the avatar image
    #[serde(skip)]
    pub our_avatar_image: Option<StatefulProtocol>,
    pub contacts: Vec<Contact>,
}

#[derive(Default, Serialize, Deserialize)]
pub(crate) struct Contact {
    pub alias: String,
    pub avatar: String, // BASE64 encoded image
    pub remote_did: String,
    pub our_did: String,
    pub our_keys: Vec<Secret>,
    pub messages: Vec<Message>,
}

impl ClientConfig {
    pub fn load(file: &str) -> Result<Self, std::io::Error> {
        let contents = std::fs::read_to_string(file)?;
        let config: ClientConfig = serde_json::from_str(&contents)?;
        Ok(config)
    }

    pub fn save(config: &ClientConfig, file: &str) -> Result<(), std::io::Error> {
        let contents = serde_json::to_string(config)?;
        std::fs::write(file, contents)
    }
}
