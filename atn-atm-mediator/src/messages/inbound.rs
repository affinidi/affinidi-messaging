use std::borrow::BorrowMut;

use atn_atm_didcomm::{envelope::MetaEnvelope, Message, UnpackOptions};
use atn_atm_sdk::messages::sending::{InboundMessageList, InboundMessageResponse};
use did_peer::DIDPeer;
use ssi::did::DIDMethods;
use tracing::{debug, error, span, warn, Instrument};

use crate::{
    common::errors::{MediatorError, Session},
    messages::MessageHandler,
    SharedData,
};

pub(crate) async fn handle_inbound(
    state: &SharedData,
    session: &Session,
    message: &str,
) -> Result<InboundMessageResponse, MediatorError> {
    let _span = span!(
        tracing::Level::DEBUG,
        "handle_inbound",
        session_id = session.session_id.as_str()
    );

    async move {
        let mut did_method_resolver = DIDMethods::default();
        did_method_resolver.insert(Box::new(DIDPeer));
        let mut did_resolver = state.did_resolver.clone();

        let mut envelope = match MetaEnvelope::new(
            message,
            did_resolver.borrow_mut(),
            &state.config.mediator_secrets,
            &did_method_resolver,
        )
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
            &mut did_resolver,
            &did_method_resolver,
            &state.config.mediator_secrets,
            &UnpackOptions::default(),
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
        let response = msg.process(state, session).await?;
        debug!("message processed:\n{:#?}", response);

        // Store the message if necessary
        if response.store_message {
            let mut stored_messages = InboundMessageList::default();
            if let Some(response) = &response.message {
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

                for recipient in to_dids {
                    let (msg_str, _msg_metadata) = response
                        .pack(
                            recipient,
                            &state.config.mediator_did,
                            &metadata,
                            &state.config.mediator_secrets,
                            &did_resolver,
                        )
                        .await?;

                    match state
                        .database
                        .store_message(
                            &session.session_id,
                            &msg_str,
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
            Ok(InboundMessageResponse::Stored(stored_messages))
        } else if let Some(message) = response.message {
            let (packed, _) = message
                .pack(
                    &session.did,
                    &state.config.mediator_did,
                    &metadata,
                    &state.config.mediator_secrets,
                    &did_resolver,
                )
                .await?;
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