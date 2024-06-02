use axum::{
    extract::{Path, State},
    Json,
};
use didcomm::UnpackMetadata;
use http::StatusCode;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::{
    common::errors::{AppError, GenericDataStruct, Session, SuccessResponse},
    SharedData,
};

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct ResponseData {
    pub body: String,
    pub metadata: UnpackMetadata,
}
impl GenericDataStruct for ResponseData {}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "lowercase")]
pub enum Folder {
    Inbox,
    Outbox,
}

/// Retrieves lists of messages either from the send or receive queue
pub async fn message_list_handler(
    session: Session,
    Path(folder): Path<Folder>,
    State(state): State<SharedData>,
) -> Result<(StatusCode, Json<SuccessResponse<ResponseData>>), AppError> {
    debug!("ALl Good!!!");
    let messages = state.database.list_messages(&session.did, folder).await?;

    debug!("Messages: {:#?}", messages);

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
