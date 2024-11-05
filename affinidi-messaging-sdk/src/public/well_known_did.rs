use crate::{errors::ATMError, messages::SuccessResponse, profiles::Profile, ATM};
use tracing::{debug, span, Level};

impl ATM {
    /// Helper method to get the Mediators well-known DID
    pub async fn well_known_did(&mut self, profile: &Profile) -> Result<String, ATMError> {
        let _span = span!(Level::DEBUG, "well_known_did").entered();

        debug!("Sending well_known_did request");

        let Some(mediator_url) = profile.get_mediator_rest_endpoint() else {
            return Err(ATMError::TransportError(
                "No mediator url found".to_string(),
            ));
        };

        let well_known_did_atm_api = [&mediator_url, "/.well-known/did"].concat();
        debug!("API well_known_did_api({})", well_known_did_atm_api);

        let res = self
            .inner
            .read()
            .await
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
