use tracing::{debug, span, Level};

use crate::{errors::ATMError, ATM};

use super::DeleteMessageRequest;

impl<'c> ATM<'c> {
    /// Delete messages from ATM
    /// - messages: List of message_ids to delete
    pub async fn delete_messages(
        &mut self,
        messages: &DeleteMessageRequest,
    ) -> Result<(), ATMError> {
        let _span = span!(Level::DEBUG, "delete_messages").entered();

        // Check if authenticated
        let tokens = self.authenticate().await?;

        let msg = serde_json::to_string(messages).map_err(|e| {
            ATMError::HTTPSError(format!(
                "Could not serialize delete message request: {:?}",
                e
            ))
        })?;

        debug!("Sending delete_messages request: {:?}", msg);

        let res = self
            .client
            .delete(format!("{}/delete", self.config.atm_api))
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", tokens.access_token))
            .body(msg)
            .send()
            .await
            .map_err(|e| {
                ATMError::HTTPSError(format!("Could not send delete_messages request: {:?}", e))
            })?;

        let status = res.status();
        debug!("API response: status({})", status);

        let body = res
            .text()
            .await
            .map_err(|e| ATMError::HTTPSError(format!("Couldn't get body: {:?}", e)))?;

        if !status.is_success() {
            debug!("Failed to get response body. Body: {:?}", body);
        }

        Ok(())
    }
}
