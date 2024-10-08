use crate::{
    common::errors::{MediatorError, Session},
    database::DatabaseHandler,
    messages::{MessageHandler, PackOptions},
    SharedData,
};
use affinidi_messaging_didcomm::{envelope::MetaEnvelope, Message, UnpackOptions};
use affinidi_messaging_sdk::messages::sending::{InboundMessageList, InboundMessageResponse};
use tracing::{debug, error, span, trace, warn, Instrument};

pub(crate) async fn handle_inbound(
    state: &SharedData,
    session: &Session,
    message: &str,
) -> Result<InboundMessageResponse, MediatorError> {
    let _span = span!(tracing::Level::DEBUG, "handle_inbound",);

    async move {
        let mut envelope =
            match MetaEnvelope::new(message, &state.did_resolver, &state.config.mediator_secrets)
                .await
            {
                Ok(envelope) => envelope,
                Err(e) => {
                    return Err(MediatorError::ParseError(
                        session.session_id.clone(),
                        "Raw inbound DIDComm message".into(),
                        e.to_string(),
                    ));
                }
            };
        debug!("message converted to MetaEnvelope");

        // Unpack the message
        let (msg, metadata) = match Message::unpack(
            &mut envelope,
            &state.did_resolver,
            &state.config.mediator_secrets,
            &UnpackOptions {
                crypto_operations_limit_per_message: state
                    .config
                    .crypto_operations_per_message_limit,
                ..UnpackOptions::default()
            },
        )
        .await
        {
            Ok(ok) => ok,
            Err(e) => {
                return Err(MediatorError::MessageUnpackError(
                    session.session_id.clone(),
                    format!("Couldn't unpack incoming message. Reason: {}", e),
                ));
            }
        };

        debug!("message unpacked:\n{:#?}", msg);

        // Process the message
        let message_response = msg.process(state, session).await?;
        debug!("message processed:\n{:#?}", message_response);

        // Pack the message and store it if necessary
        let packed_message = if message_response.store_message {
            let mut stored_messages = InboundMessageList::default();
            if let Some(response) = &message_response.message {
                // Pack the message for the next recipient(s)
                let to_dids = if let Some(to_did) = &response.to {
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

                if to_dids.len() > state.config.to_recipients_limit {
                    return Err(MediatorError::MessagePackError(
                        session.session_id.clone(),
                        format!("Recipient count({}) exceeds limit", to_dids.len()),
                    ));
                }

                for recipient in to_dids {
                    let (packed, _msg_metadata) = response
                        .pack(
                            recipient,
                            &state.config.mediator_did,
                            &metadata,
                            &state.config.mediator_secrets,
                            &state.did_resolver,
                            &PackOptions {
                                to_keys_per_recipient_limit: state
                                    .config
                                    .to_keys_per_recipient_limit,
                            },
                        )
                        .await?;

                    // Live stream the message?
                    if let Some(stream_uuid) = state
                        .database
                        .streaming_is_client_live(
                            &session.did_hash,
                            message_response.force_live_delivery,
                        )
                        .await
                    {
                        _live_stream(
                            &state.database,
                            &session.did_hash,
                            &stream_uuid,
                            &packed,
                            message_response.force_live_delivery,
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
                            stored_messages.messages.push((recipient.clone(), msg_id));
                        }
                        Err(e) => {
                            warn!("error storing message recipient({}): {:?}", recipient, e);
                            stored_messages
                                .errors
                                .push((recipient.clone(), e.to_string()));
                        }
                    }
                }
            }
            InboundMessageResponse::Stored(stored_messages)
        } else if let Some(message) = message_response.message {
            let (packed, meta) = message
                .pack(
                    &session.did,
                    &state.config.mediator_did,
                    &metadata,
                    &state.config.mediator_secrets,
                    &state.did_resolver,
                    &PackOptions {
                        to_keys_per_recipient_limit: state.config.to_keys_per_recipient_limit,
                    },
                )
                .await?;
            trace!("Ephemeral message packed (meta):\n{:#?}", meta);
            trace!("Ephemeral message (msg):\n{:#?}", packed);
            // Live stream the message?
            if let Some(stream_uuid) = state
                .database
                .streaming_is_client_live(&session.did_hash, message_response.force_live_delivery)
                .await
            {
                _live_stream(
                    &state.database,
                    &session.did_hash,
                    &stream_uuid,
                    &packed,
                    message_response.force_live_delivery,
                )
                .await;
            }
            InboundMessageResponse::Ephemeral(packed)
        } else {
            error!("No message to return");
            return Err(MediatorError::InternalError(
                session.session_id.clone(),
                "Expected a message to return, but got None".into(),
            ));
        };

        Ok(packed_message)
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
