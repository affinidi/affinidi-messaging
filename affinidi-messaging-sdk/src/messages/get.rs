use tracing::{debug, span, Level};

use crate::{
    errors::ATMError,
    messages::{GetMessagesResponse, SuccessResponse},
    ATM,
};

use super::GetMessagesRequest;

impl<'c> ATM<'c> {
    /// Returns a list of messages that are stored in the ATM
    /// - messages : List of message IDs to retrieve
    pub async fn get_messages(
        &mut self,
        messages: &GetMessagesRequest,
    ) -> Result<GetMessagesResponse, ATMError> {
        let _span = span!(Level::DEBUG, "get_messages").entered();

        // Check if authenticated
        let tokens = self.authenticate().await?;

        let body = serde_json::to_string(messages).map_err(|e| {
            ATMError::TransportError(format!("Could not serialize get message request: {:?}", e))
        })?;

        debug!("Sending get_messages request: {:?}", body);

        let res = self
            .client
            .post(format!("{}/outbound", self.config.atm_api))
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", tokens.access_token))
            .body(body)
            .send()
            .await
            .map_err(|e| {
                ATMError::TransportError(format!("Could not send get_messages request: {:?}", e))
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

        let body = serde_json::from_str::<SuccessResponse<GetMessagesResponse>>(&body)
            .ok()
            .unwrap();

        let list = if let Some(list) = body.data {
            list
        } else {
            return Err(ATMError::TransportError("No messages found".to_string()));
        };

        debug!(
            "response: success({}) messages, failed({}) messages, failed_deleted({}) messages",
            list.success.len(),
            list.get_errors.len(),
            list.delete_errors.len()
        );
        if !list.get_errors.is_empty() {
            for (msg, err) in &list.get_errors {
                debug!("failed get: msg({}) error({})", msg, err);
            }
        }
        if !list.delete_errors.is_empty() {
            for (msg, err) in &list.delete_errors {
                debug!("failed delete: msg({}) error({})", msg, err);
            }
        }

        Ok(list)
    }
}
