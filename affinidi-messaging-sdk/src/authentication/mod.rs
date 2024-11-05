use affinidi_messaging_didcomm::{Message, PackEncryptedOptions};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{sync::Arc, time::SystemTime};
use tokio::sync::RwLock;
use tracing::{debug, error, span, Instrument, Level};
use uuid::Uuid;

use crate::{
    errors::ATMError,
    messages::{
        AuthenticationChallenge, AuthorizationResponse, GenericDataStruct, SuccessResponse,
    },
    profiles::Profile,
    SharedState,
};

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct AuthRefreshResponse {
    pub access_token: String,
    pub access_expires_at: u64,
}
impl GenericDataStruct for AuthRefreshResponse {}

impl Profile {
    /// Authenticate the SDK against Affinidi Trusted Messaging
    ///
    /// Will loop until successful authentication
    /// Will backoff on retries to a max of 10 seconds
    pub(crate) async fn authenticate(
        &mut self,
        shared_state: &Arc<RwLock<SharedState>>,
    ) -> Result<AuthorizationResponse, ATMError> {
        let mut retry_count = 0;
        let mut timer = 1;
        loop {
            match self._authenticate(shared_state).await {
                Ok(response) => return Ok(response),
                Err(err) => {
                    retry_count += 1;
                    error!(
                        "Profile ({}): Attempt #{}. Error authenticating: {:?} :: Sleeping for ({}) seconds",
                        self.alias, retry_count, err, timer
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(timer)).await;
                    if timer < 10 {
                        timer += 1;
                    }
                }
            }
        }
    }

    // Where the bulk of the authentication logic is actually done
    async fn _authenticate(
        &mut self,
        shared_state: &Arc<RwLock<SharedState>>,
    ) -> Result<AuthorizationResponse, ATMError> {
        if self.authenticated {
            // Already authenticated

            // Check if we need to refresh the tokens
            match self._refresh_authentication(shared_state).await {
                Ok(_) => {}
                Err(err) => {
                    // Couldn't refresh the tokens
                    self.authenticated = false;
                    return Err(err);
                }
            };

            if let Some(tokens) = &self.authorization {
                return Ok(tokens.clone());
            } else {
                self.authenticated = false;
                return Err(ATMError::AuthenticationError(
                    "Authenticated but no tokens found".to_owned(),
                ));
            }
        }

        let _span = span!(Level::DEBUG, "authenticate",);
        async move {
            debug!("Retrieving authentication challenge...");

            let (profile_did, mediator_did) = self.dids()?;
            let Some(mediator_endpoint) = self.get_mediator_rest_endpoint() else {
                return Err(ATMError::AuthenticationError(
                    "there is no mediation REST endpoint".to_string(),
                ));
            };

            // Step 1. Get the challenge
            let step1_response = _http_post::<AuthenticationChallenge>(
                &shared_state.read().await.client,
                &[&mediator_endpoint, "/authenticate/challenge"].concat(),
                &format!("{{\"did\": \"{}\"}}", profile_did).to_string(),
            )
            .await?;

            debug!("Challenge received:\n{:#?}", step1_response);

            // Step 2. Sign the challenge
            let challenge = if let Some(challenge) = &step1_response.data {
                challenge
            } else {
                return Err(ATMError::AuthenticationError(
                    "No challenge received from ATM".to_owned(),
                ));
            };

            let auth_response = self._create_auth_challenge_response(challenge)?;
            debug!(
                "Auth response message:\n{}",
                serde_json::to_string_pretty(&auth_response).unwrap()
            );

            let lock = shared_state.read().await;
            let (auth_msg, _) = auth_response
                .pack_encrypted(
                    mediator_did,
                    Some(profile_did),
                    Some(profile_did),
                    &lock.did_resolver,
                    &lock.secrets_resolver,
                    &PackEncryptedOptions::default(),
                )
                .await
                .map_err(|e| {
                    ATMError::MsgSendError(format!(
                        "Couldn't pack authentication response message: {:?}",
                        e
                    ))
                })?;

            debug!("Successfully packed auth message\n{:#?}", auth_msg);

            let step2_response = _http_post::<AuthorizationResponse>(
                &lock.client,
                &[&mediator_endpoint, "/authenticate"].concat(),
                &auth_msg,
            )
            .await?;

            if let Some(tokens) = &step2_response.data {
                debug!("Tokens received:\n{:#?}", tokens);
                self.authorization = Some(tokens.clone());
                debug!("Successfully authenticated");
                self.authenticated = true;

                Ok(tokens.clone())
            } else {
                Err(ATMError::AuthenticationError(
                    "No tokens received from ATM".to_owned(),
                ))
            }
        }
        .instrument(_span)
        .await
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
        body: &AuthenticationChallenge,
    ) -> Result<Message, ATMError> {
        let (profile_did, mediator_did) = self.dids()?;
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Ok(Message::build(
            Uuid::new_v4().into(),
            "https://affinidi.com/atm/1.0/authenticate".to_owned(),
            json!(body),
        )
        .to(mediator_did.to_owned())
        .from(profile_did.to_owned())
        .created_time(now)
        .expires_time(now + 60)
        .finalize())
    }

    /// Refresh the JWT access token
    /// # Arguments
    ///   * `refresh_token` - The refresh token to be used
    /// # Returns
    /// A packed DIDComm message to be sent
    async fn _create_refresh_request(
        &self,
        refresh_token: &str,
        shared_state: &Arc<RwLock<SharedState>>,
    ) -> Result<String, ATMError> {
        let (profile_did, mediator_did) = self.dids()?;
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let refresh_message = Message::build(
            Uuid::new_v4().into(),
            "https://affinidi.com/atm/1.0/authenticate/refresh".to_owned(),
            json!(refresh_token),
        )
        .to(mediator_did.to_owned())
        .from(profile_did.to_owned())
        .created_time(now)
        .expires_time(now + 60)
        .finalize();

        let lock = shared_state.read().await;
        match refresh_message
            .pack_encrypted(
                mediator_did,
                Some(profile_did),
                Some(profile_did),
                &lock.did_resolver,
                &lock.secrets_resolver,
                &PackEncryptedOptions::default(),
            )
            .await
        {
            Ok((refresh_msg, _)) => Ok(refresh_msg),
            Err(err) => Err(ATMError::MsgSendError(format!(
                "Couldn't pack authentication refresh message: {:?}",
                err
            ))),
        }
    }

    /// Will refresh the access tokens as required
    async fn _refresh_authentication(
        &mut self,
        shared_state: &Arc<RwLock<SharedState>>,
    ) -> Result<(), ATMError> {
        if let Some(tokens) = &self.authorization {
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            // Check if the access token has or is going to expire in next 10 seconds
            if tokens.access_expires_at - 10 <= now {
                // Need to refresh the token
                if tokens.refresh_expires_at <= now {
                    // Refresh token has also expired
                    Err(ATMError::AuthenticationError(
                        "Refresh token has expired".to_owned(),
                    ))
                } else {
                    // Refresh the token

                    let Some(mediator_endpoint) = self.get_mediator_rest_endpoint() else {
                        return Err(ATMError::AuthenticationError(
                            "there is no mediation REST endpoint".to_string(),
                        ));
                    };

                    let refresh_msg = self
                        ._create_refresh_request(&tokens.refresh_token, shared_state)
                        .await?;
                    let new_tokens = _http_post::<AuthRefreshResponse>(
                        &shared_state.read().await.client,
                        &[&mediator_endpoint, "/authenticate/refresh"].concat(),
                        &refresh_msg,
                    )
                    .await?;

                    if let Some(new_tokens) = new_tokens.data {
                        self.authorization = Some(AuthorizationResponse {
                            access_token: new_tokens.access_token,
                            access_expires_at: new_tokens.access_expires_at,
                            refresh_token: tokens.refresh_token.clone(),
                            refresh_expires_at: tokens.refresh_expires_at,
                        });
                        debug!("JWT successfully refreshed");
                        Ok(())
                    } else {
                        Err(ATMError::AuthenticationError(
                            "No tokens received from ATM".to_owned(),
                        ))
                    }
                }
            } else {
                // No need to refresh the token
                Ok(())
            }
        } else {
            Err(ATMError::AuthenticationError(
                "No tokens found to refresh".to_owned(),
            ))
        }
    }
}

async fn _http_post<T: GenericDataStruct>(
    client: &Client,
    url: &str,
    body: &str,
) -> Result<SuccessResponse<T>, ATMError> {
    debug!("POSTing to {}", url);
    debug!("Body: {}", body);
    let response = client
        .post(url)
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .map_err(|e| ATMError::TransportError(format!("HTTP POST failed ({}): {:?}", url, e)))?;

    let response_status = response.status();
    let response_body = response
        .text()
        .await
        .map_err(|e| ATMError::TransportError(format!("Couldn't get body: {:?}", e)))?;

    if !response_status.is_success() {
        return Err(ATMError::AuthenticationError(format!(
            "Failed to get authentication response. url: {}, status: {}",
            url, response_status
        )));
    }

    debug!("response body: {}", response_body);
    serde_json::from_str::<SuccessResponse<T>>(&response_body).map_err(|e| {
        ATMError::AuthenticationError(format!("Couldn't deserialize AuthorizationResponse: {}", e))
    })
}
