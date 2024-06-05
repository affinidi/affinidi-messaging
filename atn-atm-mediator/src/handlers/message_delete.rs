use atn_atm_didcomm::UnpackMetadata;
use atn_atm_sdk::messages::{
    list::{Folder, MessageList},
    DeleteMessageRequest, GenericDataStruct,
};
use axum::{
    extract::{Path, State},
    Json,
};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use tracing::{debug, span, Instrument, Level};

use crate::{
    common::errors::{AppError, Session, SuccessResponse},
    SharedData,
};

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct ResponseData {
    pub body: String,
    pub metadata: UnpackMetadata,
}
impl GenericDataStruct for ResponseData {}

/// Deletes a specific message from ATM
/// Returns a list of messages that were deleted
pub async fn message_delete_handler(
    session: Session,
    State(state): State<SharedData>,
    Json(body): Json<DeleteMessageRequest>,
) -> Result<(StatusCode, Json<SuccessResponse<MessageList>>), AppError> {
    let _span = span!(
        Level::DEBUG,
        "message_delete_handler",
        session = session.session_id,
        did = session.did,
    );
    async move {
        debug!("Deleting ({}) messages", body.message_ids.len());
        let mut deleted: MessageList = Vec::new();

        for message in &body.message_ids {
            debug!("Deleting message: message_id({})", message);
            deleted.push(
                state
                    .database
                    .delete_messages(&session.session_id, &session.did, message)
                    .await?,
            );
        }

        Ok((
            StatusCode::OK,
            Json(SuccessResponse {
                sessionId: session.session_id,
                httpCode: StatusCode::OK.as_u16(),
                errorCode: 0,
                errorCodeStr: "NA".to_string(),
                message: "Success".to_string(),
                data: None,
            }),
        ))
    }
    .instrument(_span)
    .await
}
