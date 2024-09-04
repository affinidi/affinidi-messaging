use atn_atm_sdk::messages::SuccessResponse;
use axum::{extract::State, Json};
use http::StatusCode;
use tracing::{event, span, Instrument, Level};

use crate::{common::errors::AppError, SharedData};

pub async fn well_known_did_fetch_handler(
    State(state): State<SharedData>,
) -> Result<(StatusCode, Json<SuccessResponse<String>>), AppError> {
    let _span = span!(Level::DEBUG, "well_known_jwks_fetch_handler");
    async move {
        let did = state.config.clone().mediator_did;

        Ok((
            StatusCode::OK,
            Json(SuccessResponse {
                sessionId: "".to_string(),
                data: Some(did),
                httpCode: StatusCode::OK.as_u16(),
                errorCode: 0,
                errorCodeStr: "NA".to_string(),
                message: "Success".to_string(),
            }),
        ))
    }
    .instrument(_span)
    .await
}
