use crate::{
    common::errors::{MediatorError, Session},
    messages::{store::store_message, MessageHandler},
    SharedData,
};
use affinidi_messaging_didcomm::{envelope::MetaEnvelope, Message, UnpackOptions};
use affinidi_messaging_sdk::messages::sending::InboundMessageResponse;
use tracing::{debug, span, Instrument};

pub(crate) async fn handle_inbound(
    state: &SharedData,
    session: &Session,
    message: &str,
) -> Result<InboundMessageResponse, MediatorError> {
    let _span = span!(tracing::Level::DEBUG, "handle_inbound",);

    async move {
        let mut envelope = match MetaEnvelope::new(
            message,
            &state.did_resolver,
            &state.config.security.mediator_secrets,
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

        // Unpack the message
        let (msg, metadata) = match Message::unpack(
            &mut envelope,
            &state.did_resolver,
            &state.config.security.mediator_secrets,
            &UnpackOptions {
                crypto_operations_limit_per_message: state
                    .config
                    .limits
                    .crypto_operations_per_message,
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

        store_message(state, session, &message_response, &metadata).await
    }
    .instrument(_span)
    .await
}
