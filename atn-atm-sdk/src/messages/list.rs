use super::GenericDataStruct;
use crate::{errors::ATMError, messages::SuccessResponse, ATM};
use serde::{Deserialize, Serialize};
use sha256::digest;
use std::fmt::{Debug, Display};
use tracing::{debug, span, Level};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "lowercase")]
pub enum Folder {
    Inbox,
    Outbox,
}

impl Display for Folder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Folder::Inbox => write!(f, "inbox"),
            Folder::Outbox => write!(f, "outbox"),
        }
    }
}

/// A list of messages that are stored in the ATM for a given DID
/// - msg-id: The unique identifier of the message
/// - list-id: The unique identifier of the element in the list the message is stored in
/// - msg-size: The size of the message in bytes
/// - msg-date: The date the message was stored in the ATM (milliseconds since epoch)
/// - msg-address: The address of the message in the ATM. This can be either sender or recipient depending on folder
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct MessageListElement {
    pub msg_id: String,
    pub list_id: String,
    pub msg_size: u64,
    pub msg_date: u64,
    pub msg_address: String,
}
impl GenericDataStruct for MessageListElement {}

pub type MessageList = Vec<MessageListElement>;
impl GenericDataStruct for MessageList {}

impl<'c> ATM<'c> {
    /// Returns a list of messages that are stored in the ATM
    /// # Parameters
    /// - `did`: The DID to list messages for
    /// - `folder`: The folder to list messages from
    pub async fn list_messages(
        &mut self,
        did: &str,
        folder: Folder,
    ) -> Result<MessageList, ATMError> {
        let _span = span!(Level::DEBUG, "list_messages", folder = folder.to_string()).entered();
        debug!("listing folder({}) for DID({})", did, folder);

        // Check that DID exists in DIDResolver, add it if not
        if !self.did_resolver.contains(did) {
            debug!("DID not found in resolver, adding...");
            self.add_did(did).await?;
        }

        // Check if authenticated
        let tokens = self.authenticate().await?;

        let res = self
            .client
            .get(format!(
                "{}/list/{}/{}",
                self.config.atm_api,
                digest(did),
                folder,
            ))
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", tokens.access_token))
            .send()
            .await
            .map_err(|e| {
                ATMError::HTTPSError(format!("Could not send list_messages request: {:?}", e))
            })?;

        let status = res.status();
        debug!("API response: status({})", status);

        let body = res
            .text()
            .await
            .map_err(|e| ATMError::HTTPSError(format!("Couldn't get body: {:?}", e)))?;

        if !status.is_success() {
            return Err(ATMError::HTTPSError(format!(
                "Status not successful. status({}), response({})",
                status, body
            )));
        }

        let body = serde_json::from_str::<SuccessResponse<MessageList>>(&body)
            .ok()
            .unwrap();

        let list = if let Some(list) = body.data {
            list
        } else {
            return Err(ATMError::HTTPSError("No messages found".to_string()));
        };

        debug!("List contains ({}) messages", list.len());

        Ok(list)
    }
}
