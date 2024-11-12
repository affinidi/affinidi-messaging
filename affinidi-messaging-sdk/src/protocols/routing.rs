//! DIDComm Routing Protocol
//! https://identity.foundation/didcomm-messaging/spec/#routing-protocol-20
//!
//! The DIDComm Routing Protocol is used to route messages between agents. It is used to ensure that messages are delivered to the correct agent.
//!

use crate::{errors::ATMError, profiles::Profile, ATM};
use affinidi_messaging_didcomm::{Attachment, Message, PackEncryptedOptions};
use base64::prelude::*;
use serde_json::{json, Number, Value};
use tracing::{span, Instrument, Level};
use uuid::Uuid;
#[derive(Default)]
pub struct Routing {}

impl Routing {
    /// Takes a DIDComm message and constructs a new message that is forwarded to the target DID.
    /// The message is forwarded to the target DID using the routing protocol.
    /// - atm: The Affinidi Messaging instance
    /// - message: The message to be forwarded
    /// - target_did: The DID of the target agent (typically a mediator)
    /// - next_did: The DID of the next agent to forward the message to
    /// - expires_time: The time at which the message expires if not delivered
    /// - delay_milli: The time to wait before delivering the message
    ///                NOTE: If negative, picks a random delay between 0 and the absolute value
    #[allow(clippy::too_many_arguments)]
    pub async fn forward_message(
        &self,
        atm: &ATM,
        profile: &Profile,
        message: &str,
        target_did: &str,
        next_did: &str,
        expires_time: Option<u64>,
        delay_milli: Option<i64>,
    ) -> Result<String, ATMError> {
        let _span = span!(Level::DEBUG, "forward_message");

        async move {
            let id = Uuid::new_v4();

            let attachment = Attachment::base64(BASE64_URL_SAFE_NO_PAD.encode(message)).finalize();

            let mut forwarded = Message::build(
                id.into(),
                "https://didcomm.org/routing/2.0/forward".to_owned(),
                json!({"next": next_did}),
            )
            .to(target_did.to_owned())
            .from(profile.did.clone())
            .attachment(attachment);

            if let Some(expires_time) = expires_time {
                forwarded = forwarded.expires_time(expires_time);
            }
            if let Some(delay_milli) = delay_milli {
                forwarded = forwarded.header(
                    "delay_milli".to_string(),
                    Value::Number(Number::from(delay_milli)),
                );
            }
            let forwarded = forwarded.finalize();

            // Pack the message
            let (msg, _) = forwarded
                .pack_encrypted(
                    target_did,
                    Some(&profile.did),
                    Some(&profile.did),
                    &atm.inner.did_resolver,
                    &atm.inner.secrets_resolver,
                    &PackEncryptedOptions::default(),
                )
                .await
                .map_err(|e| ATMError::MsgSendError(format!("Error packing message: {}", e)))?;

            Ok(msg)
        }
        .instrument(_span)
        .await
    }
}
