use serde::{Deserialize, Serialize};
use tracing::{debug, span, Level};

use crate::{errors::ATMError, messages::SuccessResponse, ATM};

use super::{DeleteMessageRequest, GenericDataStruct};

/// Response from message_delete
/// - successful: Contains list of message_id's that were deleted successfully
/// - errors: Contains a list of message_id's and error messages for failed deletions
#[derive(Default, Serialize, Deserialize)]
pub struct DeleteMessageResponse {
    pub success: Vec<String>,
    pub errors: Vec<(String, String)>,
}
impl GenericDataStruct for DeleteMessageResponse {}

impl<'c> ATM<'c> {
    /// Delete messages from ATM
    /// - messages: List of message_ids to delete
    pub async fn delete_messages(
        &mut self,
        messages: &DeleteMessageRequest,
    ) -> Result<DeleteMessageResponse, ATMError> {
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
            return Err(ATMError::HTTPSError(format!(
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
            return Err(ATMError::HTTPSError("No messages found".to_string()));
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
