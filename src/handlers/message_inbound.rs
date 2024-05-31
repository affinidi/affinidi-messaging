use axum::{extract::State, Json};
use did_peer::DIDPeer;
use didcomm::{envelope::MetaEnvelope, Message, UnpackMetadata, UnpackOptions};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use ssi::did::DIDMethods;
use std::borrow::BorrowMut;
use tracing::{debug, span, Level};

use crate::{
    common::errors::{AppError, GenericDataStruct, MediatorError, Session, SuccessResponse},
    messages::MessageHandler,
    SharedData,
};

#[derive(Serialize, Deserialize, Debug)]
pub struct RecipientHeader {
    pub kid: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Recipient {
    pub header: RecipientHeader,
    pub encrypted_key: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct InboundMessage {
    pub protected: String,
    pub recipients: Vec<Recipient>,
    pub iv: String,
    pub ciphertext: String,
    pub tag: String,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct InboundMessageResponse {
    pub body: String,
    pub metadata: UnpackMetadata,
}
impl GenericDataStruct for InboundMessageResponse {}

pub async fn message_inbound_handler(
    session: Session,
    State(state): State<SharedData>,
    Json(body): Json<InboundMessage>,
) -> Result<(StatusCode, Json<SuccessResponse<InboundMessageResponse>>), AppError> {
    let _span = span!(Level::DEBUG, "message_inbound_handler", session = %session.session_id);
    let s = serde_json::to_string(&body).unwrap();

    let mut did_method_resolver = DIDMethods::default();
    did_method_resolver.insert(Box::new(DIDPeer));
    let mut did_resolver = state.did_resolver.clone();

    let mut envelope = match MetaEnvelope::new(
        &s,
        did_resolver.borrow_mut(),
        &state.config.mediator_secrets,
        &did_method_resolver,
    )
    .await
    {
        Ok(envelope) => envelope,
        Err(e) => {
            return Err(MediatorError::ParseError(
                session.session_id,
                "Raw inbound DIDComm message".into(),
                e.to_string(),
            )
            .into());
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
                session.session_id,
                format!("Couldn't unpack incoming message. Reason: {}", e),
            )
            .into());
        }
    };

    debug!("message unpacked:\n{:#?}", msg);

    // Process the message
    let response = match msg.process(&session) {
        Ok(response) => response,
        Err(e) => return Err(e.into()),
    };
    debug!("message processed:\n{:#?}", response);

    // Store the message if necessary
    let msg_count = if let Some(response) = &response {
        // Pack the message for the next recipient(s)
        let to_dids = if let Some(to_did) = &response.to {
            to_did
        } else {
            return Err(MediatorError::MessagePackError(
                session.session_id,
                "No recipients found".into(),
            )
            .into());
        };

        let mut msg_count = 0;
        for recipient in to_dids {
            let msg_str = response
                .pack(
                    recipient,
                    &state.config.mediator_did,
                    &metadata,
                    &state.config.mediator_secrets,
                    &did_resolver,
                )
                .await?;

            state
                .database
                .store_message(&session.session_id, &msg_str, &envelope)
                .await?;

            msg_count += 1;
        }
        msg_count
    } else {
        0
    };

    let response = Some(InboundMessageResponse {
        body: format!("messages saved successfully count({})", msg_count),
        metadata,
    });

    Ok((
        StatusCode::OK,
        Json(SuccessResponse {
            sessionId: session.session_id,
            httpCode: StatusCode::OK.as_u16(),
            errorCode: 0,
            errorCodeStr: "NA".to_string(),
            message: "Success".to_string(),
            data: response,
        }),
    ))
}
