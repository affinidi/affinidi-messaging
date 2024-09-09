use serde::{Deserialize, Serialize};
use tracing::{debug, span, Level};

use crate::{
    errors::ATMError,
    messages::{DeleteMessageRequest, SuccessResponse},
    ATM,
};

use super::{FetchDeletePolicy, GetMessagesResponse};

/// fetch_messages() options
#[derive(Serialize, Deserialize, Debug)]
pub struct FetchOptions {
    /// The maximum number of messages to fetch. Default: 10
    pub limit: usize,
    /// The receive_id to start fetching from. Default: None. Starts with oldest message
    pub start_id: Option<String>,
    /// Delete policy for messages after fetching. Default: DoNotDelete
    pub delete_policy: FetchDeletePolicy,
}

impl Default for FetchOptions {
    fn default() -> Self {
        FetchOptions {
            limit: 10,
            start_id: None,
            delete_policy: FetchDeletePolicy::DoNotDelete,
        }
    }
}

impl<'c> ATM<'c> {
    /// Fetches any available messages from your ATM inbox
    /// This differs from the `get_messages()` function in that you don't need to know the message_id in advance
    ///
    /// # Option Fields
    ///
    /// * `limit`         - The maximum number of messages to fetch (default: 10, minimum: 1, maximum: 100)
    /// * `start_id`      - The message_id to start fetching from (default: Starts with oldest message)
    /// * `delete_policy` - Delete policy for messages after fetching (default: DoNotDelete)
    ///
    /// Calling fetch with no start_id and default delete_policy will result in the same messages being retrieved again and again
    ///
    /// # Example
    /// ```ignore
    /// // Use default options
    /// let messages = atm.fetch_messages(&FetchOptions::default()).await?;
    ///
    /// // Use custom options
    /// let messages = atm.fetch_messages(&FetchOptions {start_id: Some("12345689-0".to_string()), ..FetchOptions::default()}).await?;
    /// ```
    pub async fn fetch_messages(
        &mut self,
        options: &FetchOptions,
    ) -> Result<GetMessagesResponse, ATMError> {
        let _span = span!(
            Level::DEBUG,
            "fetch_messages",
            limit = options.limit,
            start_id = options.start_id,
            delete_policy = options.delete_policy.to_string()
        )
        .entered();

        // Check if limit is within bounds
        if options.limit < 1 || options.limit > 100 {
            return Err(ATMError::ConfigError(format!(
                "FetchOptions.limit must be between 1 and 100 inclusive. Got: {}",
                options.limit
            )));
        }

        // Check if authenticated
        let tokens = self.authenticate().await?;

        let body = serde_json::to_string(options).map_err(|e| {
            ATMError::TransportError(format!(
                "Could not serialize fetch_message() options: {:?}",
                e
            ))
        })?;

        let res = self
            .client
            .post(format!("{}/fetch", self.config.atm_api,))
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", tokens.access_token))
            .body(body)
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

        let body = serde_json::from_str::<SuccessResponse<GetMessagesResponse>>(&body)
            .ok()
            .unwrap();

        let mut list = if let Some(list) = body.data {
            list
        } else {
            return Err(ATMError::TransportError("No messages found".to_string()));
        };

        if let FetchDeletePolicy::OnReceive = options.delete_policy {
            match self
                .delete_messages(&DeleteMessageRequest {
                    message_ids: list.success.iter().map(|m| m.msg_id.clone()).collect(),
                })
                .await
            {
                Ok(r) => {
                    debug!("Messages deleted: ({})", r.success.len());
                    list.delete_errors.extend(r.errors);
                }
                Err(e) => {
                    debug!("Error deleting messages: ({})", e);
                    list.delete_errors = list
                        .success
                        .iter()
                        .map(|m| (m.msg_id.clone(), "ERROR".to_string()))
                        .collect();
                }
            }
        }

        debug!(
            "response: success({}) messages, failed_deleted({}) messages",
            list.success.len(),
            list.delete_errors.len()
        );
        if !list.delete_errors.is_empty() {
            for (msg, err) in &list.delete_errors {
                debug!("failed delete: msg({}) error({})", msg, err);
            }
        }

        Ok(list)
    }
}
