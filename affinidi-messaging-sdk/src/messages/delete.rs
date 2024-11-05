use tracing::{debug, span, Level};

use crate::{errors::ATMError, messages::SuccessResponse, profiles::Profile, ATM};

use super::{DeleteMessageRequest, DeleteMessageResponse};

const MAX_DELETED_MESSAGES: usize = 100;

impl ATM {
    /// Delete messages from ATM
    /// - messages: List of message_ids to delete
    pub async fn delete_messages(
        &self,
        profile: &mut Profile,
        messages: &DeleteMessageRequest,
    ) -> Result<DeleteMessageResponse, ATMError> {
        let _span = span!(Level::DEBUG, "delete_messages").entered();

        // Check if authenticated
        let tokens = profile.authenticate(&self.inner).await?;
        if messages.message_ids.len() > MAX_DELETED_MESSAGES {
            return  Err(ATMError::MsgSendError(format!(
                "Operation exceeds the allowed limit. You may delete a maximum of 100 messages per request. Received {} ids.",
                messages.message_ids.len()
            )));
        }
        let msg = serde_json::to_string(messages).map_err(|e| {
            ATMError::TransportError(format!(
                "Could not serialize delete message request: {:?}",
                e
            ))
        })?;

        let Some(mediator_url) = profile.get_mediator_rest_endpoint() else {
            return Err(ATMError::TransportError(
                "No mediator URL found".to_string(),
            ));
        };
        debug!("Sending delete_messages request: {:?}", msg);

        let res = self
            .inner
            .read()
            .await
            .client
            .delete([&mediator_url, "/delete"].concat())
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", tokens.access_token))
            .body(msg)
            .send()
            .await
            .map_err(|e| {
                ATMError::TransportError(format!("Could not send delete_messages request: {:?}", e))
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

        let body = serde_json::from_str::<SuccessResponse<DeleteMessageResponse>>(&body)
            .ok()
            .unwrap();

        let list = if let Some(list) = body.data {
            list
        } else {
            return Err(ATMError::TransportError("No messages found".to_string()));
        };

        debug!(
            "response: success({}) messages, failed({}) messages",
            list.success.len(),
            list.errors.len()
        );
        if !list.errors.is_empty() {
            for (msg, err) in &list.errors {
                debug!("failed: msg({}) error({})", msg, err);
            }
        }

        Ok(list)
    }
}
