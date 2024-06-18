use super::GenericDataStruct;
use crate::{errors::ATMError, transports::SendMessageResponse, ATM};
use atn_atm_didcomm::{Message, PackEncryptedOptions};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::SystemTime;
use tracing::{debug, span, Level};
use uuid::Uuid;

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
    /// Sends a DIDComm Trust-Ping message
    /// - `to_did` - The DID to send the ping to
    /// - `signed` - Whether the ping should signed or anonymous?
    /// - `expect_response` - Whether a response is expected[^note]
    ///
    /// [^note]: Anonymous pings cannot expect a response, the SDK will automatically set this to false if anonymous is true
    pub async fn send_ping(
        &mut self,
        to_did: &str,
        signed: bool,
        expect_response: bool,
    ) -> Result<SendMessageResponse, ATMError> {
        let _span = span!(Level::DEBUG, "create_ping_message",).entered();
        debug!(
            "Pinging {}, signed?({}) response_expected?({})",
            to_did, signed, expect_response
        );

        // Check that DID exists in DIDResolver, add it if not
        if !self.did_resolver.contains(to_did) {
            debug!("DID not found in resolver, adding...");
            self.add_did(to_did).await?;
        }

        // If an anonymous ping is being sent, we should ensure that expect_response is false
        let expect_response = if !signed && expect_response {
            debug!("Anonymous pings cannot expect a response, changing to false...");
            false
        } else {
            expect_response
        };

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut msg = Message::build(
            Uuid::new_v4().into(),
            "https://didcomm.org/trust-ping/2.0/ping".to_owned(),
            json!({"response_requested": expect_response}),
        )
        .to(to_did.to_owned());

        let from_did = if !signed {
            // Can support anonymous pings
            None
        } else {
            msg = msg.from(self.config.my_did.clone());
            Some(self.config.my_did.clone())
        };
        let msg = msg.created_time(now).expires_time(now + 300).finalize();

        debug!("Ping message: {:?}", msg);

        // Pack the message
        let (msg, _) = msg
            .pack_encrypted(
                to_did,
                from_did.as_deref(),
                from_did.as_deref(),
                &self.did_resolver,
                &self.secrets_resolver,
                &PackEncryptedOptions::default(),
            )
            .await
            .map_err(|e| ATMError::MsgSendError(format!("Error packing message: {}", e)))?;

        if self.ws_stream.is_some() {
            self.ws_send_didcomm_message(&msg).await
        } else {
            self.send_didcomm_message(&msg).await
        }
    }
}
