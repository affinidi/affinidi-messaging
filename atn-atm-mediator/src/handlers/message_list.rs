use atn_atm_didcomm::UnpackMetadata;
use atn_atm_sdk::messages::{
    list::{Folder, MessageList},
    GenericDataStruct,
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

/// Retrieves lists of messages either from the send or receive queue
pub async fn message_list_handler(
    session: Session,
    Path(folder): Path<Folder>,
    State(state): State<SharedData>,
) -> Result<(StatusCode, Json<SuccessResponse<MessageList>>), AppError> {
    let _span = span!(
        Level::DEBUG,
        "message_list_handler",
        session = session.session_id,
        did = session.did,
        folder = folder.to_string()
    );
    async move {
        let messages = state.database.list_messages(&session.did, folder).await?;

        debug!("List contains ({}) messages", messages.len());
        Ok((
            StatusCode::OK,
            Json(SuccessResponse {
                sessionId: session.session_id,
                httpCode: StatusCode::OK.as_u16(),
                errorCode: 0,
                errorCodeStr: "NA".to_string(),
                message: "Success".to_string(),
                data: Some(messages),
            }),
        ))
    }
    .instrument(_span)
    .await
}
