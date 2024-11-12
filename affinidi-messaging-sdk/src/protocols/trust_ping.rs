use std::{sync::Arc, time::SystemTime};

use affinidi_messaging_didcomm::{Message, PackEncryptedOptions};
use serde_json::json;
use sha256::digest;
use tokio::sync::RwLock;
use tracing::{debug, span, Level};
use uuid::Uuid;

use crate::{errors::ATMError, messages::EmptyResponse, profiles::Profile, ATM};

#[derive(Default)]
pub struct TrustPing {}

/// Used to construct the response for a TrustPing message
/// - `message_id` - The ID of the message sent
/// - `message_hash` - The sha256 hash of the message sent
/// - `bytes` - The number of bytes sent
pub struct TrustPingSent {
    pub message_id: String,
    pub message_hash: String,
    pub bytes: u32,
    pub response: Option<String>,
}

impl TrustPing {
    /// Sends a DIDComm Trust-Ping message
    /// - `to_did` - The DID to send the ping to
    /// - `signed` - Whether the ping should signed or anonymous?
    /// - `expect_response` - Whether a response is expected[^note]
    ///
    /// Returns: The message ID and sha256 hash of the ping message
    /// [^note]: Anonymous pings cannot expect a response, the SDK will automatically set this to false if anonymous is true
    pub async fn send_ping(
        &self,
        atm: &ATM,
        profile: &Arc<RwLock<Profile>>,
        to_did: &str,
        signed: bool,
        expect_response: bool,
    ) -> Result<TrustPingSent, ATMError> {
        let _span = span!(Level::DEBUG, "create_ping_message",).entered();
        debug!(
            "Pinging {}, signed?({}) response_expected?({})",
            to_did, signed, expect_response
        );
        let _profile = profile.read().await;
        let (profile_did, _) = _profile.dids()?;
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
            msg = msg.from(profile_did.to_string());
            Some(profile_did)
        };
        let msg = msg.created_time(now).expires_time(now + 300).finalize();
        let mut msg_info = TrustPingSent {
            message_id: msg.id.clone(),
            message_hash: "".to_string(),
            bytes: 0,
            response: None,
        };

        debug!("Ping message: {:#?}", msg);

        // Pack the message
        let (msg, _) = msg
            .pack_encrypted(
                to_did,
                from_did,
                from_did,
                &atm.inner.did_resolver,
                &atm.inner.secrets_resolver,
                &PackEncryptedOptions::default(),
            )
            .await
            .map_err(|e| ATMError::MsgSendError(format!("Error packing message: {}", e)))?;

        debug!("Packed message: {:#?}", msg);

        msg_info.message_hash = digest(&msg).to_string();
        msg_info.bytes = msg.len() as u32;

        atm.send_message::<EmptyResponse>(profile, &msg, &msg_info.message_id)
            .await?;
        Ok(msg_info)
    }
}
