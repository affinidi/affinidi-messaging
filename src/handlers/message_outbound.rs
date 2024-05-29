use axum::{extract::State, Json};
use did_peer::DIDPeer;
use didcomm::{envelope::MetaEnvelope, Message, UnpackMetadata, UnpackOptions};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use ssi::did::DIDMethods;
use std::borrow::BorrowMut;

use crate::{
    common::errors::{AppError, GenericDataStruct, MediatorError, Session, SuccessResponse},
    messages::MessageHandler,
    SharedData,
};

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct ResponseData {
    pub body: String,
    pub metadata: UnpackMetadata,
}
impl GenericDataStruct for ResponseData {}

#[derive(Serialize, Deserialize, Debug)]
pub struct InboundMessage {
    pub did: String,
}

pub async fn message_outbound_handler(
    session: Session,
    State(state): State<SharedData>,
    Json(body): Json<InboundMessage>,
) -> Result<(StatusCode, Json<SuccessResponse<ResponseData>>), AppError> {
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

    // Process the message
    let response = match msg.process(&session) {
        Ok(response) => response,
        Err(e) => return Err(e.into()),
    };

    // Store the message if necessary
    let response = if let Some(response) = &response {
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

        let recipient = to_dids.first().unwrap();
        Some(
            response
                .pack(
                    recipient,
                    &state.config.mediator_did,
                    &metadata,
                    &state.config.mediator_secrets,
                    &did_resolver,
                )
                .await?,
        )
    } else {
        None
    };

    let response = response.map(|response| ResponseData {
        body: response,
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
