use std::time::SystemTime;

use didcomm::{Message, PackEncryptedOptions};
use serde_json::json;
use tracing::{debug, span, Level};
use uuid::Uuid;

use crate::{errors::ATMError, messages::InboundMessageResponse, ATM};

impl<'c> ATM<'c> {
    /// Sends a trust ping message to the specified DID
    /// - `to_did` - The DID to send the ping to
    /// - `anonymous` - Whether the ping should be sent anonymously
    /// - `expect_response` - Whether a response is expected[^note]
    ///
    /// [^note]: Anonymous pings cannot expect a response, the SDK will automatically set this to false if anonymous is true
    pub async fn send_ping(
        &mut self,
        to_did: &str,
        anonymous: bool,
        expect_response: bool,
    ) -> Result<(), ATMError> {
        let _span = span!(Level::DEBUG, "send_ping",).entered();
        debug!(
            "Pinging {}, anonymous?({}) response_expected?({})",
            to_did, anonymous, expect_response
        );

        // Check that DID exists in DIDResolver, add it if not
        if !self.did_resolver.contains(to_did) {
            debug!("DID not found in resolver, adding...");
            self.add_did(to_did).await?;
        }

        // If an anonymous ping is being sent, we should ensure that expect_response is false
        let expect_response = if anonymous && expect_response {
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

        let from_did = if anonymous {
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

        // send the message
        let response = self.send_message::<InboundMessageResponse>(&msg).await?;

        debug!("Response: {:?}", response);

        Ok(())
    }
}
