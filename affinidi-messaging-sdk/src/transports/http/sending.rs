use crate::{
    errors::ATMError,
    messages::{GenericDataStruct, SuccessResponse},
    transports::SendMessageResponse,
    ATM,
};
use tracing::{debug, span, Level};

impl<'c> ATM<'c> {
    /// send_didcomm_message
    /// - msg: Packed DIDComm message that we want to send
    /// - return_response: Whether to return the response from the API
    pub async fn send_didcomm_message<T>(
        &mut self,
        message: &str,
        return_response: bool,
    ) -> Result<SendMessageResponse<T>, ATMError>
    where
        T: GenericDataStruct,
    {
        let _span = span!(Level::DEBUG, "send_message",).entered();
        let tokens = self.authenticate().await?;

        let msg = message.to_owned();

        let res = self
            .client
            .post(format!("{}/inbound", self.config.atm_api))
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", tokens.access_token))
            .body(msg)
            .send()
            .await
            .map_err(|e| ATMError::TransportError(format!("Could not send message: {:?}", e)))?;

        let status = res.status();
        debug!("API response: status({})", status);

        let body = res
            .text()
            .await
            .map_err(|e| ATMError::TransportError(format!("Couldn't get body: {:?}", e)))?;

        if !status.is_success() {
            return Err(ATMError::TransportError(format!(
                "API returned an error: status({}), body({})",
                status, body
            )));
        }
        debug!("body =\n{}", body);
        let http_response: Option<T> = if return_response {
            let r: SuccessResponse<T> = serde_json::from_str(&body).map_err(|e| {
                ATMError::TransportError(format!("Couldn't parse response: {:?}", e))
            })?;
            r.data
        } else {
            None
        };

        Ok(SendMessageResponse::RestAPI(http_response))
    }
}
