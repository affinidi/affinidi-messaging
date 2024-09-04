use crate::{
    errors::ATMError,
    messages::{DIDDocument, SuccessResponse},
    ATM,
};
use tracing::{debug, span, Level};

impl<'c> ATM<'c> {
    /// Returns a list of messages that are stored in the ATM
    /// - messages : List of message IDs to retrieve
    pub async fn well_known_did_json(&mut self) -> Result<DIDDocument, ATMError> {
        let _span = span!(Level::DEBUG, "well_known_did_json").entered();

        debug!("Sending well_known_did_json request");

        let atm_api = self.config.clone().atm_api;
        debug!(
            "API well_known_did_json_api({})",
            format!("{}/.well-known/did.json", atm_api)
        );

        let res = self
            .client
            .get(format!("{}/.well-known/did.json", atm_api))
            .header("Content-Type", "application/json")
            .send()
            .await
            .map_err(|e| {
                ATMError::TransportError(format!(
                    "Could not send get well-known did.json request: {:?}",
                    e
                ))
            })?;

        let status = res.status();
        debug!("API response: status({})", status);
        // let string_body = res
        //     .text()
        //     .await
        //     .map_err(|e| ATMError::TransportError(format!("Couldn't get string body: {:?}", e)))?;

        let body: SuccessResponse<DIDDocument> = res.json().await.map_err(|e| {
            ATMError::TransportError(format!("Couldn't get didDocument body: {:?}", e))
        })?;

        // let body_parsed: SuccessResponse<DIDDocument> = serde_json::from_str(&string_body)
        //     .map_err(|e| {
        //         ATMError::TransportError(format!("Couldn't get didDocument body: {:?}", e))
        //     })?;
        let did_doc_parsed = body.data.unwrap();
        if !status.is_success() {
            return Err(ATMError::TransportError(format!(
                "Status not successful. status({}), response({})",
                status,
                serde_json::to_string(&did_doc_parsed).map_err(|e| ATMError::TransportError(
                    format!("Couldn't stringify body: {:?}", e)
                ))?
            )));
        }

        // debug!(
        //     "API response: body({})",
        //     serde_json::to_string(body).map_err(|e| ATMError::TransportError(format!(
        //         "Couldn't stringify body: {:?}",
        //         e
        //     )))?
        // );

        Ok(did_doc_parsed)
    }
}
