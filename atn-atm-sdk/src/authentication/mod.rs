use std::time::SystemTime;

use atn_atm_didcomm::{Message, PackEncryptedOptions};
use serde_json::json;
use tracing::{debug, span, Level};
use uuid::Uuid;

use crate::{
    errors::ATMError,
    messages::{AuthenticationChallenge, AuthorizationResponse, SuccessResponse},
    ATM,
};

impl<'c> ATM<'c> {
    /// Authenticate the SDK against Affinidi Trusted Messaging
    pub async fn authenticate(&mut self) -> Result<AuthorizationResponse, ATMError> {
        if self.authenticated {
            // Already authenticated
            if let Some(tokens) = &self.jwt_tokens {
                return Ok(tokens.clone());
            } else {
                return Err(ATMError::AuthenticationError(
                    "Authenticated but no tokens found".to_owned(),
                ));
            }
        }

        let _span = span!(Level::DEBUG, "authenticate",).entered();

        debug!("Retrieving authentication challenge...");
        // Step 1. Get the challenge
        let res = self
            .client
            .post(format!("{}/authenticate/challenge", self.config.atm_api))
            .header("Content-Type", "application/json")
            .body(format!("{{\"did\": \"{}\"}}", self.config.my_did).to_string())
            .send()
            .await
            .map_err(|e| {
                ATMError::HTTPSError(format!(
                    "retrieving authentication challenge failed. Reason: {:?}",
                    e
                ))
            })?;
        let status = res.status();
        debug!("Challenge response: status({})", status);

        let body = res
            .text()
            .await
            .map_err(|e| ATMError::HTTPSError(format!("Couldn't get body: {:?}", e)))?;

        if !status.is_success() {
            debug!("Failed to get authentication challenge. Body: {:?}", body);
            return Err(ATMError::AuthenticationError(
                "Failed to get authentication challenge".to_owned(),
            ));
        }
        let body = serde_json::from_str::<SuccessResponse<AuthenticationChallenge>>(&body)
            .ok()
            .unwrap();

        debug!("Challenge received:\n{:#?}", body);

        // Step 2. Sign the challenge
        let challenge = if let Some(challenge) = &body.data {
            challenge
        } else {
            return Err(ATMError::AuthenticationError(
                "No challenge received from ATM".to_owned(),
            ));
        };

        let auth_response = self._create_auth_challenge_response(&self.config.atm_did, challenge);
        debug!("Auth response message:\n{:#?}", auth_response);

        let (auth_msg, _) = auth_response
            .pack_encrypted(
                &self.config.atm_did,
                Some(&self.config.my_did),
                Some(&self.config.my_did),
                &self.did_resolver,
                &self.secrets_resolver,
                &PackEncryptedOptions::default(),
            )
            .await
            .map_err(|e| {
                ATMError::MsgSendError(format!(
                    "Couldn't pack authentication response message: {:?}",
                    e
                ))
            })?;

        debug!("Successfully packed auth message");

        let res = self
            .client
            .post(format!("{}/authenticate", self.config.atm_api))
            .header("Content-Type", "application/json")
            .body(auth_msg)
            .send()
            .await
            .map_err(|e| {
                ATMError::HTTPSError(format!("Could not post authentication response: {:?}", e))
            })?;

        let status = res.status();
        debug!("Authentication response: status({})", status);

        let body = res
            .text()
            .await
            .map_err(|e| ATMError::HTTPSError(format!("Couldn't get body: {:?}", e)))?;

        if !status.is_success() {
            debug!("Failed to get authentication response. Body: {:?}", body);
            return Err(ATMError::AuthenticationError(
                "Failed to get authentication response".to_owned(),
            ));
        }
        let body =
            serde_json::from_str::<SuccessResponse<AuthorizationResponse>>(&body).map_err(|e| {
                ATMError::AuthenticationError(format!(
                    "Couldn't deserialize AuthorizationResponse: {}",
                    e
                ))
            })?;

        if let Some(tokens) = &body.data {
            debug!("Tokens received:\n{:#?}", tokens);
            self.jwt_tokens = Some(tokens.clone());
            debug!("Successfully authenticated");
            self.authenticated = true;

            Ok(tokens.clone())
        } else {
            Err(ATMError::AuthenticationError(
                "No tokens received from ATM".to_owned(),
            ))
        }
    }

    /// Creates an Affinidi Trusted Messaging Authentication Challenge Response Message
    /// # Arguments
    /// * `atm_did` - The DID for ATM
    /// * `challenge` - The challenge that was sent
    /// # Returns
    /// A DIDComm message to be sent
    ///
    /// Notes:
    /// - This message will expire after 60 seconds
    fn _create_auth_challenge_response(
        &self,
        atm_did: &str,
        body: &AuthenticationChallenge,
    ) -> Message {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Message::build(
            Uuid::new_v4().into(),
            "https://affinidi.com/atm/1.0/authenticate".to_owned(),
            json!(body),
        )
        .to(atm_did.to_owned())
        .from(self.config.my_did.to_owned())
        .created_time(now)
        .expires_time(now + 60)
        .finalize()
    }
}
