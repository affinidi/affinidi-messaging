use crate::{errors::ATMError, messages::SuccessResponse, ATM};
use tracing::{debug, span, Level};

impl<'c> ATM<'c> {
    /// Helper method to get the Mediators well-known DID
    pub async fn well_known_did(&mut self) -> Result<String, ATMError> {
        let _span = span!(Level::DEBUG, "well_known_did").entered();

        debug!("Sending well_known_did request");

        let well_known_did_atm_api = format!("{}/.well-known/did", self.config.clone().atm_api);
        debug!("API well_known_did_api({})", well_known_did_atm_api);

        let res = self
            .client
            .get(well_known_did_atm_api)
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
        let body = res
            .text()
            .await
            .map_err(|e| ATMError::TransportError(format!("Couldn't get string body: {:?}", e)))?;

        let body = serde_json::from_str::<SuccessResponse<String>>(&body)
            .ok()
            .unwrap();

        if !status.is_success() {
            return Err(ATMError::TransportError(format!(
                "Status not successful. status({}), response({:?})",
                status, body
            )));
        }

        let did = if let Some(did) = body.data {
            did
        } else {
            return Err(ATMError::TransportError("No did found".to_string()));
        };

        debug!("API response: did({})", did);

        Ok(did)
    }
}
