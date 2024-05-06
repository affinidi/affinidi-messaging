use axum::{
    extract::{Path, State},
    Json,
};
use http::StatusCode;
use serde::{Deserialize, Serialize};

use crate::{
    common::errors::{AppError, GenericDataStruct, Session, SuccessResponse},
    SharedData,
};

#[derive(Deserialize, Debug)]
pub struct InboundMessage {
    pub name: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct ResponseData {
    pub name: String,
}
impl GenericDataStruct for ResponseData {}

pub async fn message_inbound_handler(
    session: Session,
    State(state): State<SharedData>,
    Path(org_guid): Path<String>,
    Json(body): Json<InboundMessage>,
) -> Result<(StatusCode, Json<SuccessResponse<ResponseData>>), AppError> {
    let response_data = ResponseData {
        name: body.name.unwrap_or_else(|| "Anonymous".to_string()),
    };

    Ok((
        StatusCode::OK,
        Json(SuccessResponse {
            transactionID: session.tx_id,
            httpCode: StatusCode::OK.as_u16(),
            errorCode: 0,
            errorCodeStr: "NA".to_string(),
            message: "Success".to_string(),
            data: response_data,
        }),
    ))
}
