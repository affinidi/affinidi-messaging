use atn_atm_sdk::messages::{DIDDocument, SuccessResponse};
use axum::{extract::State, Json};
use did_peer::resolve_did_peer;
use http::StatusCode;
use tracing::{event, span, Instrument, Level};

use crate::{
    common::errors::{AppError, MediatorError},
    SharedData,
};

pub async fn well_known_did_fetch_handler(
    State(state): State<SharedData>,
) -> Result<(StatusCode, Json<SuccessResponse<DIDDocument>>), AppError> {
    let _span = span!(Level::DEBUG, "well_known_jwks_fetch_handler");
    async move {
        let did = state.config.clone().mediator_did;
        let did_doc = resolve_did_peer(&did).await.map_err(|err| {
            event!(Level::ERROR, "Could not resolve did. {}", err);
            MediatorError::DIDError(
                "SessionId".to_string(),
                "NA".into(),
                format!("Could not resolve did. {}", err),
            )
        })?;

        let did_doc_parsed: DIDDocument = serde_json::from_str(&did_doc).map_err(|err| {
            event!(Level::ERROR, "Could not parse DidDocument. {}", err);
            MediatorError::DIDError(
                "SessionId".to_string(),
                "NA".into(),
                format!("Could not parse DidDocument. {}", did_doc),
            )
        })?;

        Ok((
            StatusCode::OK,
            Json(SuccessResponse {
                sessionId: "".to_string(),
                data: Some(did_doc_parsed),
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
