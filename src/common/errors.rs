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
    #[error("Error in handling errors! {1}")]
    ErrorHandlingError(TxId, String),
    #[error("{1}")]
    InternalError(TxId, String),
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
    #[error("DID Error: did({1}) Error: {2}")]
    DIDError(TxId, String, String),
    #[error("Configuration Error: {1}")]
    ConfigError(TxId, String),
    #[error("Database Error: {1}")]
    DatabaseError(TxId, String),
    #[error("Message unpack error: {1}")]
    MessageUnpackError(TxId, String),
    #[error("MessageExpired: expiry({1}) now({2})")]
    MessageExpired(TxId, String, String),
    #[error("Message pack error: {1}")]
    MessagePackError(TxId, String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let response = match self.0 {
            MediatorError::ErrorHandlingError(tx_id, msg) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                    transactionID: tx_id.to_string(),
                    errorCode: 1,
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
                    errorCode: 2,
                    errorCodeStr: "InternalError".to_string(),
                    message: msg.to_string(),
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::ParseError(tx_id, _, msg) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::BAD_REQUEST.as_u16(),
                    transactionID: tx_id.to_string(),
                    errorCode: 3,
                    errorCodeStr: "BadRequest: ParseError".to_string(),
                    message: msg.to_string(),
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::PermissionError(tx_id, msg) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::FORBIDDEN.as_u16(),
                    transactionID: tx_id.to_string(),
                    errorCode: 4,
                    errorCodeStr: "Forbidden: PermissionError".to_string(),
                    message: msg.to_string(),
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::RequestDataError(tx_id, msg) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::BAD_REQUEST.as_u16(),
                    transactionID: tx_id.to_string(),
                    errorCode: 5,
                    errorCodeStr: "BadRequest: RequestDataError".to_string(),
                    message: format!("Bad Request: ({})", msg),
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::ServiceLimitError(tx_id, msg) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::BAD_REQUEST.as_u16(),
                    transactionID: tx_id.to_string(),
                    errorCode: 6,
                    errorCodeStr: "BadRequest: ServiceLimitError".to_string(),
                    message: msg.to_string(),
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
            MediatorError::DIDError(tx_id, did, msg) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::BAD_REQUEST.as_u16(),
                    transactionID: tx_id.to_string(),
                    errorCode: 8,
                    errorCodeStr: "DIDError".to_string(),
                    message: format!("did({}) Error: {}", did, msg),
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::ConfigError(tx_id, message) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                    transactionID: tx_id.to_string(),
                    errorCode: 9,
                    errorCodeStr: "ConfigError".to_string(),
                    message,
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::DatabaseError(tx_id, message) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                    transactionID: tx_id.to_string(),
                    errorCode: 10,
                    errorCodeStr: "DatabaseError".to_string(),
                    message,
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::MessageUnpackError(tx_id, message) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::BAD_REQUEST.as_u16(),
                    transactionID: tx_id.to_string(),
                    errorCode: 11,
                    errorCodeStr: "MessageUnpackError".to_string(),
                    message,
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::MessageExpired(tx_id, expired, now) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::UNPROCESSABLE_ENTITY.as_u16(),
                    transactionID: tx_id.to_string(),
                    errorCode: 12,
                    errorCodeStr: "MessageExpired".to_string(),
                    message: format!("Message expired: expiry({}) now({})", expired, now),
                };
                event!(Level::WARN, "{}", response.to_string());
                response
            }
            MediatorError::MessagePackError(tx_id, message) => {
                let response = ErrorResponse {
                    httpCode: StatusCode::BAD_REQUEST.as_u16(),
                    transactionID: tx_id.to_string(),
                    errorCode: 13,
                    errorCodeStr: "MessagePackError".to_string(),
                    message,
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
    pub tx_id: String,                  // Unique session transaction ID
    pub remote_addr: String,            // Remote Socket address
    pub authenticated: bool,            // Has this session been authenticated?
    pub challenge_sent: Option<String>, // Challenge sent to the client
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
    pub data: Option<T>,
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
        data: Option<T>,
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
