use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use rand::{distributions::Alphanumeric, Rng};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fmt;
use thiserror::Error;
use tracing::{event, Level};

type TxId = String;

pub struct AppError(MediatorError);

impl<E> From<E> for AppError
where
    E: Into<MediatorError>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

/// MediatorError the first String is always the tx_id
#[derive(Error, Debug)]
pub enum MediatorError {
    #[error("Element ({1}) already exists")]
    AlreadyExists(TxId, String),
    #[error("Error in handling errors! {1}")]
    ErrorHandlingError(TxId, String),
    #[error("Element ({1}) has ({2}) direct children still")]
    HasChildren(TxId, String, i32),
    #[error("{1}")]
    InternalError(TxId, String),
    #[error("Structure is locked to change")]
    LockError(TxId),
    #[error("Element ({1}) not found")]
    NotFound(TxId, String),
    #[error("Couldn't parse ({1}). Reason: {2}")]
    ParseError(TxId, String, String),
    #[error("Permission Error: {1}")]
    PermissionError(TxId, String),
    #[error("Request is invalid: {1}")]
    RequestDataError(TxId, String),
    #[error("Service Limit exceeded: {1}")]
    ServiceLimitError(TxId, String),
    #[error("Unauthorized: {1}")]
    Unauthorized(TxId, String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let response = match self.0 {
            MediatorError::AlreadyExists(tx_id, element) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::FORBIDDEN.as_u16(),
                    transactionID: tx_id.to_string(),
                    errorCode: 1,
                    errorCodeStr: "AlreadyExists".to_string(),
                    message: format!("Element ({}) already exists", element),
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::ErrorHandlingError(tx_id, msg) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                    transactionID: tx_id.to_string(),
                    errorCode: 2,
                    errorCodeStr: "ErrorHandlingError".to_string(),
                    message: msg.to_string(),
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::InternalError(tx_id, msg) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                    transactionID: tx_id.to_string(),
                    errorCode: 3,
                    errorCodeStr: "InternalError".to_string(),
                    message: msg.to_string(),
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::LockError(tx_id) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                    transactionID: tx_id.to_string(),
                    errorCode: 4,
                    errorCodeStr: "StructureLockError".to_string(),
                    message:
                        "Structure is currently locked due to changes occurring. Please try again"
                            .into(),
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::NotFound(tx_id, element) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::NOT_FOUND.as_u16(),
                    transactionID: tx_id.to_string(),
                    errorCode: 5,
                    errorCodeStr: "NotFound".to_string(),
                    message: format!("Element ({}) not found", element),
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::RequestDataError(tx_id, element) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::BAD_REQUEST.as_u16(),
                    transactionID: tx_id.to_string(),
                    errorCode: 6,
                    errorCodeStr: "BadRequest".to_string(),
                    message: format!("Bad Request: ({})", element),
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::Unauthorized(tx_id, msg) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::UNAUTHORIZED.as_u16(),
                    transactionID: tx_id.to_string(),
                    errorCode: 7,
                    errorCodeStr: "Unauthorized".to_string(),
                    message: format!("Unauthorized access: {}", msg),
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            _ => {
                event!(
                    Level::WARN,
                    "unknown MediatorError ({:?}) matched on MediatorError::response()",
                    self.0
                );
                let response = ErrorResponse {
                    httpCode: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                    transactionID: "UNKNOWN".into(),
                    errorCode: 8,
                    errorCodeStr: "ErrorHandlingError".to_string(),
                    message: format!("Unknown error code ({:?})", self.0),
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
        };
        (
            StatusCode::from_u16(response.httpCode).ok().unwrap(),
            Json(response),
        )
            .into_response()
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Session {
    pub tx_id: String,      // Unique session transaction ID
    pub project_id: String, // Affinidi Project ID - Legacy
    pub owner_id: String,   // Affinidi Owner ID - Legacy
}

#[derive(Serialize, Debug)]
#[allow(non_snake_case)]
pub struct ErrorResponse {
    pub transactionID: String,
    pub httpCode: u16,
    pub errorCode: u16,
    pub errorCodeStr: String,
    pub message: String,
}

impl fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}: httpcode({}) errorCode({}), errorCodeStr({}) message({})",
            self.transactionID, self.httpCode, self.errorCode, self.errorCodeStr, self.message,
        )
    }
}

pub trait GenericDataStruct: DeserializeOwned + Serialize {}

#[derive(Serialize, Deserialize, Debug)]
#[allow(non_snake_case)]
pub struct SuccessResponse<T: GenericDataStruct> {
    pub transactionID: String,
    pub httpCode: u16,
    pub errorCode: i32,
    pub errorCodeStr: String,
    pub message: String,
    #[serde(bound(deserialize = ""))]
    pub data: T,
}

impl<T: GenericDataStruct> fmt::Display for SuccessResponse<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}: httpcode({}) errorCode({}), errorCodeStr({}) message({})",
            self.transactionID, self.httpCode, self.errorCode, self.errorCodeStr, self.message,
        )
    }
}

impl<T: GenericDataStruct> SuccessResponse<T> {
    pub fn response(
        tx_id: &str,
        http_code: StatusCode,
        msg: &str,
        data: T,
    ) -> Json<SuccessResponse<T>> {
        let response = SuccessResponse {
            transactionID: tx_id.to_string(),
            httpCode: http_code.as_u16(),
            errorCode: 0,
            errorCodeStr: "Ok".to_string(),
            message: msg.to_string(),
            data,
        };
        event!(Level::INFO, "{response}");
        Json(response)
    }
}

// Creates a random transaction identifier for each transaction
pub fn create_tx_id() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect()
}
