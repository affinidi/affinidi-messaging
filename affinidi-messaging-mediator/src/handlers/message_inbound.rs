use affinidi_messaging_sdk::messages::sending::InboundMessageResponse;
use axum::{extract::State, Json};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use tracing::{span, Instrument, Level};

use crate::{
    common::errors::{AppError, MediatorError, SuccessResponse},
    database::session::Session,
    messages::inbound::handle_inbound,
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

pub async fn message_inbound_handler(
    session: Session,
    State(state): State<SharedData>,
    Json(body): Json<InboundMessage>,
) -> Result<(StatusCode, Json<SuccessResponse<InboundMessageResponse>>), AppError> {
    let _span = span!(
        Level::DEBUG,
        "message_inbound_handler",
        session = session.session_id
    );
    async move {
        let s = match serde_json::to_string(&body) {
            Ok(s) => s,
            Err(e) => {
                return Err(MediatorError::ParseError(
                    session.session_id.clone(),
                    "InboundMessage".into(),
                    e.to_string(),
                )
                .into());
            }
        };

        let response = handle_inbound(&state, &session, &s).await?;

        Ok((
            StatusCode::OK,
            Json(SuccessResponse {
                sessionId: session.session_id,
                httpCode: StatusCode::OK.as_u16(),
                errorCode: 0,
                errorCodeStr: "NA".to_string(),
                message: "Success".to_string(),
                data: Some(response),
            }),
        ))
    }
    .instrument(_span)
    .await
}
