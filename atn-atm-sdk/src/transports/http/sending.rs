use crate::{errors::ATMError, messages::GenericDataStruct, transports::SendMessageResponse, ATM};
use serde::{Deserialize, Serialize};
use sha256::digest;
use tracing::{debug, span, Level};

/// Response from the ATM API when sending a message
/// Contains a list of messages that were sent
/// - messages : List of successful stored messages (recipient, message_ids)
/// - errors   : List of errors that occurred while storing messages (recipient, error)
///
/// NOTE: Sending a single message can result in multiple forward messages being sent!
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct InboundMessageResponse {
    pub messages: Vec<(String, String)>,
    pub errors: Vec<(String, String)>,
}
impl GenericDataStruct for InboundMessageResponse {}

impl<'c> ATM<'c> {
    /// send_didcomm_message
    /// - msg: Packed DIDComm message that we want to send
    pub async fn send_didcomm_message(
        &mut self,
        message: &str,
    ) -> Result<SendMessageResponse, ATMError> {
        let _span = span!(Level::DEBUG, "send_message",).entered();
        let tokens = self.authenticate().await?;

        let msg = message.to_owned();

        let res = self
            .client
            .post(format!("{}/inbound", self.config.atm_api))
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", tokens.access_token))
            .body(msg)
            .send()
            .await
            .map_err(|e| ATMError::TransportError(format!("Could not send message: {:?}", e)))?;

        let status = res.status();
        debug!("API response: status({})", status);

        let body = res
            .text()
            .await
            .map_err(|e| ATMError::TransportError(format!("Couldn't get body: {:?}", e)))?;

        if !status.is_success() {
            return Err(ATMError::TransportError(format!(
                "API returned an error: status({}), body({})",
                status, body
            )));
        }

        Ok(SendMessageResponse {
            message_digest: digest(message),
            bytes_sent: message.len() as u32,
        })
    }
}
