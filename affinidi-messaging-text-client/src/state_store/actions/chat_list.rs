/*!
 * State for managing the list of chats
 */

use std::{collections::HashMap, fmt, hash::Hasher};

use affinidi_messaging_sdk::profiles::{Profile, ProfileConfig};
use circular_queue::CircularQueue;
use serde::{Deserialize, Serialize};
use std::hash::Hash;

use crate::state_store::chat_message::ChatMessage;

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
        status: ChatStatus,
    ) {
        let chat = Chat {
            name: name.to_string(),
            description: description.to_string(),
            our_profile: ProfileConfig::from(our_profile).await,
            remote_did,
            invitation_link,
            status,
            ..Default::default()
        };

        self.chats.insert(name.to_string(), chat);
    }

    /// Find a chat by our local DID
    pub fn find_chat_by_did(&self, did: &str) -> Option<Chat> {
        self.chats
            .values()
            .find(|c| c.our_profile.did.as_str() == did)
            .cloned()
    }

    /// Find a chat by name
    pub fn find_chat_by_name(&self, name: &str) -> Option<Chat> {
        self.chats.get(name).cloned()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChatStatus {
    AwaitingInvitationAcceptance,
    EstablishedChannel,
}

impl fmt::Display for ChatStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChatStatus::AwaitingInvitationAcceptance => write!(f, "Awaiting Invitation Acceptance"),
            ChatStatus::EstablishedChannel => write!(f, "Established Secure Channel"),
        }
    }
}

fn _true() -> bool {
    true
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chat {
    pub name: String,
    pub status: ChatStatus,
    pub description: String,
    pub messages: CircularQueue<ChatMessage>,
    pub our_profile: ProfileConfig,
    pub remote_did: Option<String>,
    pub has_unread: bool,
    // This is used to store the invitation link for the chat
    pub invitation_link: Option<String>,
    #[serde(skip, default = "_true")]
    pub initialization: bool,
}

impl PartialEq for Chat {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Eq for Chat {}

impl Hash for Chat {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state);
    }
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
            initialization: true,
        }
    }
}
