use super::errors::{ErrorResponse, Session};
use crate::common::errors::create_tx_id;
use axum::{
    async_trait,
    extract::FromRequestParts,
    response::{IntoResponse, Response},
    Json, RequestPartsExt,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use base64::prelude::*;
use http::{request::Parts, StatusCode};
use itertools::Itertools;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{event, Level};

const SKEW: u64 = 30; // We allow for a 30 second skew on time checks

// Payload contents of the JWT
// All times are in seconds since UNIX EPOCH
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenPayload {
    pub aud: Vec<String>, // Intended Audience
    pub client_id: String,
    pub exp: u64,         // What does this JWT Expire
    pub iat: u64,         // Issued at this time
    pub iss: String,      // Who issued this JWT?
    pub jti: String,      // JWT ID
    pub nbf: u64,         // JWT is not valid before this time
    pub scp: Vec<String>, // ???
    pub sub: String,      // subject - who this JWT refers to
}

#[derive(Debug)]
pub enum AuthError {
    WrongCredentials,
    MissingCredentials,
    InvalidToken,
    ExpiredToken,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthError::WrongCredentials => (StatusCode::UNAUTHORIZED, "Wrong credentials"),
            AuthError::MissingCredentials => (StatusCode::BAD_REQUEST, "Missing credentials"),
            AuthError::InvalidToken => (StatusCode::BAD_REQUEST, "Invalid token"),
            AuthError::ExpiredToken => (StatusCode::UNAUTHORIZED, "Expired credentials"),
        };
        let body = Json(json!(ErrorResponse {
            transactionID: "UNAUTHORIZED".into(),
            httpCode: status.as_u16(),
            errorCode: status.as_u16(),
            errorCodeStr: status.to_string(),
            message: error_message.into()
        }));
        (status, body).into_response()
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for Session
where
    S: Send + Sync,
{
    type Rejection = AuthError;
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let tx_id = create_tx_id();

        /*
        event!(Level::DEBUG, "{}: INSIDE JWT Authentication", tx_id);
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| AuthError::MissingCredentials)?;

        event!(Level::DEBUG, "{}: JWT = {}", tx_id, bearer.token());

        /*
            let decode_key = DecodingKey::from_ec_components(
                "b3kdYEBrlWjQwY55F8MhXC97pwkjTpcQZZ09oDDBK4c",
                "wlopQwIPWuT55M3ZfCDZdoBs1nh2kwEvzPjnkakf96U",
            )
            .unwrap();
        // TODO: This needs to be decode() not decode_header()
        let claims = match decode_header(&token.unwrap()) {
            Ok(c) => c,
            Err(err) => {
                event!(Level::WARN, "decode failed {:?}", err);
                let json_error = ErrorResponse {
                    status: "fail".to_string(),
                    message: "Invalid token".to_string(),
                };
                return ready(Err(ErrorUnauthorized(json_error)));
            }
        };
        event!(Level::DEBUG, "claims = {:?}", claims);
        */

        let token = bearer.token();

        let jwt_parts: Vec<&str> = token.split('.').collect_vec();
        if jwt_parts.len() != 3 {
            return Err(AuthError::InvalidToken);
        }

        let payload_raw = if let Ok(payload) = BASE64_STANDARD_NO_PAD.decode(jwt_parts[1]) {
            if let Ok(payload) = String::from_utf8(payload) {
                payload
            } else {
                return Err(AuthError::InvalidToken);
            }
        } else {
            return Err(AuthError::InvalidToken);
        };
        event!(Level::DEBUG, "payload_raw = {}", payload_raw);

        // Deserialize JSON payload
        let payload = if let Ok(payload) = serde_json::from_str::<TokenPayload>(&payload_raw) {
            payload
        } else {
            return Err(AuthError::InvalidToken);
        };

        event!(Level::DEBUG, "payload = {:?}", payload);

        // Check the validity of the JWT
        let since_epoch = if let Ok(epoch) = SystemTime::now().duration_since(UNIX_EPOCH) {
            epoch.as_secs()
        } else {
            return Err(AuthError::InvalidToken);
        };
        if (payload.exp + SKEW) < since_epoch
            || (payload.iat - SKEW) > since_epoch
            || (payload.nbf - SKEW) > since_epoch
        {
            event!(
                Level::DEBUG,
                "{}: expired token epoch({}) exp({}) iat({}) nbf({})",
                tx_id,
                since_epoch,
                payload.exp,
                payload.iat,
                payload.nbf
            );
            return Err(AuthError::ExpiredToken);
        }

        // Extract the Subject which gives us the projectId
        // ari:iam::<project_id>:user/<principal_id> ...
        // ari:iam::e1f31c18-a69f-4423-b276-cbd1bf0863aa:user/ff660134-f87d-4959-8425-192609e483cb/client/e7a5c192-fc6f-4164-b010-68c4bd8bfb66"

        let sub = payload.sub.split(':').collect_vec();
        if sub.len() < 5 {
            return Err(AuthError::WrongCredentials);
        }

        let re = Regex::new(r"(user\/.[^\/]*)\/").unwrap();
        let Some(owner_id) = re.captures(sub[4]) else {
            return Err(AuthError::WrongCredentials);
        };*/

        let session = Session { tx_id };

        Ok(session)
    }
}
