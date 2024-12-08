/*!
 * State for managing the list of chats
 */

use std::{collections::HashMap, fmt};

use affinidi_messaging_sdk::profiles::{Profile, ProfileConfig};
use circular_queue::CircularQueue;
use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct ChatList {
    pub chats: HashMap<String, Chat>,
    #[serde(skip)]
    pub active_chat: Option<String>,
}

impl ChatList {
    pub async fn create_chat(
        &mut self,
        name: &str,
        description: &str,
        our_profile: &Profile,
        remote_did: Option<String>,
        invitation_link: Option<String>,
    ) {
        let chat = Chat {
            name: name.to_string(),
            description: description.to_string(),
            our_profile: ProfileConfig::from(our_profile).await,
            remote_did,
            invitation_link,
            ..Default::default()
        };

        self.chats.insert(name.to_string(), chat);
    }

    pub fn get_mut_chat(&mut self, name: &str) -> Option<&mut Chat> {
        self.chats.get_mut(name)
    }

    /// Tries to set the active chat as the given chat. Returns the [Chat] associated to the chat.
    pub fn try_set_active_chat(&mut self, name: &str) -> Option<&Chat> {
        let chat_data = self.chats.get_mut(name)?;
        chat_data.has_unread = false;

        self.active_chat = Some(String::from(name));

        Some(chat_data)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChatStatus {
    AwaitingInvitationAcceptance,
}

impl fmt::Display for ChatStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChatStatus::AwaitingInvitationAcceptance => write!(f, "Awaiting Invitation Acceptance"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chat {
    pub name: String,
    pub status: ChatStatus,
    pub description: String,
    pub messages: CircularQueue<String>,
    pub our_profile: ProfileConfig,
    pub remote_did: Option<String>,
    pub has_unread: bool,
    // This is used to store the invitation link for the chat
    pub invitation_link: Option<String>,
}

impl Default for Chat {
    fn default() -> Self {
        Chat {
            name: String::new(),
            status: ChatStatus::AwaitingInvitationAcceptance,
            description: String::new(),
            messages: CircularQueue::with_capacity(50),
            our_profile: ProfileConfig::default(),
            remote_did: None,
            has_unread: false,
            invitation_link: None,
        }
    }
}
