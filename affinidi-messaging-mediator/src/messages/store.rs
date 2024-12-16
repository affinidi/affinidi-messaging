use crate::messages::MessageHandler;
use crate::{
    common::errors::{MediatorError, Session},
    database::DatabaseHandler,
    messages::PackOptions,
    SharedData,
};
use affinidi_messaging_didcomm::{PackEncryptedMetadata, UnpackMetadata};
use affinidi_messaging_sdk::messages::sending::{InboundMessageList, InboundMessageResponse};
use sha256::digest;
use tracing::{debug, error, span, trace, warn, Instrument};

use super::ProcessMessageResponse;

/// Stores a message in the mediator's database
/// handles a lot of higher order logic for storing messages
/// - state: SharedData
/// - session: Session
/// - response: ProcessMessageResponse
/// - metadata: UnpackMetadata
pub(crate) async fn store_message(
    state: &SharedData,
    session: &Session,
    response: &ProcessMessageResponse,
    metadata: &UnpackMetadata,
) -> Result<InboundMessageResponse, MediatorError> {
    let _span = span!(tracing::Level::DEBUG, "store_message",);

    async move {
        if response.forward_message {
            Ok(InboundMessageResponse::Forwarded)
        } else if response.store_message {
            let mut stored_messages = InboundMessageList::default();
            if let Some(message) = &response.message {
                // Pack the message for the next recipient(s)
                let to_dids = if let Some(to_did) = &message.to {
                    to_did
                } else {
                    return Err(MediatorError::MessagePackError(
                        session.session_id.clone(),
                        "No recipients found".into(),
                    ));
                };
                debug!(
                    "response to_dids: count({}) vec({:?})",
                    to_dids.len(),
                    to_dids
                );

                if to_dids.len() > state.config.limits.to_recipients {
                    return Err(MediatorError::MessagePackError(
                        session.session_id.clone(),
                        format!("Recipient count({}) exceeds limit", to_dids.len()),
                    ));
                }

                for recipient in to_dids {
                    let (packed, _): (String, PackEncryptedMetadata) = message
                        .pack(
                            recipient,
                            &state.config.mediator_did,
                            metadata,
                            &state.config.security.mediator_secrets,
                            &state.did_resolver,
                            &PackOptions {
                                to_keys_per_recipient_limit: state
                                    .config
                                    .limits
                                    .to_keys_per_recipient,
                            },
                        )
                        .await?;

                    // Live stream the message?
                    if let Some(stream_uuid) = state
                        .database
                        .streaming_is_client_live(&session.did_hash, response.force_live_delivery)
                        .await
                    {
                        _live_stream(
                            &state.database,
                            &session.did_hash,
                            &stream_uuid,
                            &packed,
                            response.force_live_delivery,
                        )
                        .await;
                    }

                    match state
                        .database
                        .store_message(
                            &session.session_id,
                            &packed,
                            recipient,
                            Some(&state.config.mediator_did),
                        )
                        .await
                    {
                        Ok(msg_id) => {
                            debug!(
                                "message id({}) stored successfully recipient({})",
                                msg_id, recipient
                            );
                            stored_messages
                                .messages
                                .push((recipient.to_string(), msg_id));
                        }
                        Err(e) => {
                            warn!("error storing message recipient({}): {:?}", recipient, e);
                            stored_messages
                                .errors
                                .push((recipient.to_string(), e.to_string()));
                        }
                    }
                }
            }
            Ok(InboundMessageResponse::Stored(stored_messages))
        } else if let Some(message) = &response.message {
            let (packed, meta) = message
                .pack(
                    &session.did,
                    &state.config.mediator_did,
                    metadata,
                    &state.config.security.mediator_secrets,
                    &state.did_resolver,
                    &PackOptions {
                        to_keys_per_recipient_limit: state.config.limits.to_keys_per_recipient,
                    },
                )
                .await?;
            trace!("Ephemeral message packed (meta):\n{:#?}", meta);
            trace!("Ephemeral message (msg):\n{:#?}", packed);
            // Live stream the message?
            if let Some(stream_uuid) = state
                .database
                .streaming_is_client_live(&session.did_hash, response.force_live_delivery)
                .await
            {
                _live_stream(
                    &state.database,
                    &session.did_hash,
                    &stream_uuid,
                    &packed,
                    response.force_live_delivery,
                )
                .await;
            }
            Ok(InboundMessageResponse::Ephemeral(packed))
        } else {
            error!("No message to return");
            Err(MediatorError::InternalError(
                session.session_id.clone(),
                "Expected a message to return, but got None".into(),
            ))
        }
    }
    .instrument(_span)
    .await
}

/// If live streaming is enabled, this function will send the message to the live stream
/// Ok to ignore errors here
async fn _live_stream(
    database: &DatabaseHandler,
    did_hash: &str,
    stream_uuid: &str,
    message: &str,
    force_live_delivery: bool,
) {
    if database
        .streaming_publish_message(did_hash, stream_uuid, message, force_live_delivery)
        .await
        .is_ok()
    {
        debug!("Live streaming message to UUID: {}", stream_uuid);
    }
}

/// Stores a message in the mediator's database that has been forwarded
/// handles a lot of higher order logic for storing messages
/// - state: SharedData
/// - session: Session
/// - response: ProcessMessageResponse
/// - metadata: UnpackMetadata
pub(crate) async fn store_forwarded_message(
    state: &SharedData,
    session: &Session,
    message: &str,
    sender: &str,
    recipient: &str,
) -> Result<(), MediatorError> {
    let _span = span!(tracing::Level::DEBUG, "store_forwarded_message",);

    async move {
        let did_hash = digest(recipient);
        // Live stream the message?
        if let Some(stream_uuid) = state
            .database
            .streaming_is_client_live(&did_hash, false)
            .await
        {
            _live_stream(&state.database, &did_hash, &stream_uuid, message, false).await;
        }

        match state
            .database
            .store_message(&session.session_id, message, recipient, Some(sender))
            .await
        {
            Ok(msg_id) => {
                debug!(
                    "message id({}) stored successfully recipient({})",
                    msg_id, recipient
                );
            }
            Err(e) => {
                warn!("error storing message recipient({}): {:?}", recipient, e);
            }
        }

        Ok(())
    }
    .instrument(_span)
    .await
}
