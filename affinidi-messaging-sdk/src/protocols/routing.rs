//! DIDComm Routing Protocol
//! https://identity.foundation/didcomm-messaging/spec/#routing-protocol-20
//!
//! The DIDComm Routing Protocol is used to route messages between agents. It is used to ensure that messages are delivered to the correct agent.
//!

use affinidi_messaging_didcomm::{Message, PackEncryptedOptions};
use serde_json::json;
use tracing::{span, Instrument, Level};
use uuid::Uuid;

use crate::{errors::ATMError, ATM};
#[derive(Default)]
pub struct Routing {}

impl Routing {
    /// Takes a DIDComm message and constructs a new message that is forwarded to the target DID.
    /// The message is forwarded to the target DID using the routing protocol.
    /// - atm: The Affinidi Messaging instance
    /// - message: The message to be forwarded
    /// - target_did: The DID of the target agent (typically a mediator)
    /// - expires_time: The time at which the message expires if not delivered
    /// - delay_milli: The time to wait before delivering the message
    ///                NOTE: If negative, picks a random delay between 0 and the absolute value
    pub async fn forward_message<'c>(
        &self,
        atm: &'c mut ATM<'_>,
        message: &str,
        target_did: &str,
        expires_time: Option<u64>,
        delay_milli: Option<i64>,
    ) -> Result<String, ATMError> {
        let _span = span!(Level::DEBUG, "forward_message");

        async move {
            let id = Uuid::new_v4();

            let mut forwarded = Message::build(
                id.into(),
                "https://didcomm.org/routing/2.0/forward".to_owned(),
                json!({"next": target_did}),
            )
            .to(target_did.to_owned());

            let forwarded = forwarded.finalize();

            // Pack the message
            let (msg, _) = forwarded
                .pack_encrypted(
                    target_did,
                    Some(target_did),
                    Some(target_did),
                    &atm.did_resolver,
                    &atm.secrets_resolver,
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
