use serde::{de::DeserializeOwned, Deserialize, Serialize};

pub mod delete;
pub mod list;
pub mod sending;

/// Generic response structure for all responses from the ATM API
#[derive(Serialize, Deserialize, Debug)]
#[allow(non_snake_case)]
pub struct SuccessResponse<T: GenericDataStruct> {
    pub sessionId: String,
    pub httpCode: u16,
    pub errorCode: i32,
    pub errorCodeStr: String,
    pub message: String,
    #[serde(bound(deserialize = ""))]
    pub data: Option<T>,
}

/// Specific response structure for the authentication challenge response
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct AuthenticationChallenge {
    pub challenge: String,
    pub session_id: String,
}
impl GenericDataStruct for AuthenticationChallenge {}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct AuthorizationResponse {
    pub access_token: String,
    pub refresh_token: String,
}
impl GenericDataStruct for AuthorizationResponse {}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct DeleteMessageRequest {
    pub message_ids: Vec<String>,
}
impl GenericDataStruct for DeleteMessageRequest {}

/// Helps with deserializing the generic data field in the SuccessResponse struct
pub trait GenericDataStruct: DeserializeOwned + Serialize {}
