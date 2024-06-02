use atn_atm_didcomm::UnpackMetadata;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tracing::{debug, span, Level};

use crate::{errors::ATMError, ATM};

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
pub struct InboundMessageResponse {
    pub body: String,
    pub metadata: UnpackMetadata,
}
impl GenericDataStruct for InboundMessageResponse {}

/// Helps with deserializing the generic data field in the SuccessResponse struct
pub trait GenericDataStruct: DeserializeOwned + Serialize {}

impl<'c> ATM<'c> {
    pub async fn send_message<T>(&mut self, msg: &str) -> Result<SuccessResponse<T>, ATMError>
    where
        T: GenericDataStruct,
    {
        let _span = span!(Level::DEBUG, "send_message",).entered();
        let tokens = self.authenticate().await?;

        let msg = msg.to_owned();

        let res = self
            .client
            .post(format!("{}/inbound", self.config.atm_api))
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", tokens.access_token))
            .body(msg)
            .send()
            .await
            .map_err(|e| ATMError::HTTPSError(format!("Could not send message: {:?}", e)))?;

        let status = res.status();
        debug!("API response: status({})", status);

        let body = res
            .text()
            .await
            .map_err(|e| ATMError::HTTPSError(format!("Couldn't get body: {:?}", e)))?;

        if !status.is_success() {
            debug!("Failed to get response body. Body: {:?}", body);
        }
        let body = serde_json::from_str::<SuccessResponse<T>>(&body)
            .ok()
            .unwrap();

        Ok(body)
    }
}
