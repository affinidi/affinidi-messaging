use self::protocols::ping;
use crate::{
    common::errors::{MediatorError, Session},
    SharedData,
};
use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_messaging_didcomm::{
    secrets::SecretsResolver, Message, PackEncryptedMetadata, PackEncryptedOptions, UnpackMetadata,
};
use affinidi_messaging_sdk::messages::known::MessageType as SDKMessageType;
use protocols::{mediator_administration, mediator_local_acls, routing};
use protocols::{mediator_global_acls, message_pickup};
use std::time::SystemTime;

pub mod error_response;
pub mod inbound;
pub mod protocols;
pub(crate) mod store;

struct MessageType(SDKMessageType);

/// Helps with parsing the message type and handling higher level protocols.
/// NOTE:
///   Not all Message Types need to be handled as a protocol.
impl MessageType {
    pub(crate) async fn process(
        &self,
        message: &Message,
        state: &SharedData,
        session: &Session,
    ) -> Result<ProcessMessageResponse, MediatorError> {
        match self.0 {
            SDKMessageType::MediatorAdministration => {
                mediator_administration::process(message, state, session).await
            }
            SDKMessageType::MediatorGlobalACLManagement => {
                mediator_global_acls::process(message, state, session).await
            }
            SDKMessageType::MediatorLocalACLManagement => {
                mediator_local_acls::process(message, state, session).await
            }
            SDKMessageType::TrustPing => ping::process(message, session),
            SDKMessageType::MessagePickupStatusRequest => {
                message_pickup::status_request(message, state, session).await
            }
            SDKMessageType::MessagePickupDeliveryRequest => {
                message_pickup::delivery_request(message, state, session).await
            }
            SDKMessageType::MessagePickupMessagesReceived => {
                message_pickup::messages_received(message, state, session).await
            }
            SDKMessageType::MessagePickupLiveDeliveryChange => {
                message_pickup::toggle_live_delivery(message, state, session).await
            }
            SDKMessageType::AffinidiAuthenticate => Err(MediatorError::NotImplemented(
                session.session_id.clone(),
                "Affinidi Authentication is only handled by the Authorization handler".into(),
            )),
            SDKMessageType::ForwardRequest => routing::process(message, state, session).await,
            SDKMessageType::ProblemReport => Err(MediatorError::NotImplemented(
                session.session_id.clone(),
                "Problem Report is only handled by the Error handler".into(),
            )),
            SDKMessageType::Other(_) => Err(MediatorError::NotImplemented(
                session.session_id.clone(),
                "Unknown message type".into(),
            )),
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct ProcessMessageResponse {
    pub store_message: bool,
    pub force_live_delivery: bool, // Will force a live delivery attempt.
    pub forward_message: bool, // Set to true if the message was forwarded. Means we don't need to store it.
    pub message: Option<Message>,
}

#[derive(Debug)]
pub struct PackOptions {
    pub to_keys_per_recipient_limit: usize,
}

impl Default for PackOptions {
    fn default() -> Self {
        PackOptions {
            to_keys_per_recipient_limit: 100,
        }
    }
}

pub(crate) trait MessageHandler {
    /// Processes an incoming message, determines any additional actions to take
    /// Returns a message to store and deliver if necessary
    async fn process(
        &self,
        state: &SharedData,
        session: &Session,
    ) -> Result<ProcessMessageResponse, MediatorError>;

    /// Uses the incoming unpack metadata to determine best way to pack the message
    async fn pack<S>(
        &self,
        to_did: &str,
        mediator_did: &str,
        metadata: &UnpackMetadata,
        secrets_resolver: &S,
        did_resolver: &DIDCacheClient,
        pack_options: &PackOptions,
    ) -> Result<(String, PackEncryptedMetadata), MediatorError>
    where
        S: SecretsResolver;
}

impl MessageHandler for Message {
    async fn process(
        &self,
        state: &SharedData,
        session: &Session,
    ) -> Result<ProcessMessageResponse, MediatorError> {
        let msg_type = MessageType(self.type_.as_str().parse::<SDKMessageType>().map_err(
            |err| {
                MediatorError::ParseError(
                    session.session_id.clone(),
                    "msg.type".into(),
                    err.to_string(),
                )
            },
        )?);

        // Check if message expired
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if let Some(expires) = self.expires_time {
            if expires <= now {
                return Err(MediatorError::MessageExpired(
                    "-1".into(),
                    expires.to_string(),
                    now.to_string(),
                ));
            }
        }

        msg_type.process(self, state, session).await
    }

    async fn pack<S>(
        &self,
        to_did: &str,
        mediator_did: &str,
        metadata: &UnpackMetadata,
        secrets_resolver: &S,
        did_resolver: &DIDCacheClient,
        pack_options: &PackOptions,
    ) -> Result<(String, PackEncryptedMetadata), MediatorError>
    where
        S: SecretsResolver,
    {
        if metadata.encrypted {
            // Respond with an encrypted message
            let a = match self
                .pack_encrypted(
                    to_did,
                    self.from.as_deref(),
                    Some(mediator_did),
                    did_resolver,
                    secrets_resolver,
                    &PackEncryptedOptions {
                        to_kids_limit: pack_options.to_keys_per_recipient_limit,
                        ..PackEncryptedOptions::default()
                    },
                )
                .await
            {
                Ok(msg) => msg,
                Err(e) => {
                    return Err(MediatorError::MessagePackError("-1".into(), e.to_string()));
                }
            };

            Ok(a)
        } else {
            Err(MediatorError::MessagePackError(
                "-1".into(),
                "PACK METHOD NOT IMPLEMENTED".into(),
            ))
        }
    }
}
