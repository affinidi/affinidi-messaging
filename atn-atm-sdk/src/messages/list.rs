use super::{Folder, MessageList};
use crate::{errors::ATMError, messages::SuccessResponse, ATM};
use sha256::digest;
use tracing::{debug, span, Level};

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
                ATMError::TransportError(format!("Could not send list_messages request: {:?}", e))
            })?;

        let status = res.status();
        debug!("API response: status({})", status);

        let body = res
            .text()
            .await
            .map_err(|e| ATMError::TransportError(format!("Couldn't get body: {:?}", e)))?;

        if !status.is_success() {
            return Err(ATMError::TransportError(format!(
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
            return Err(ATMError::TransportError("No messages found".to_string()));
        };

        debug!("List contains ({}) messages", list.len());

        Ok(list)
    }
}
