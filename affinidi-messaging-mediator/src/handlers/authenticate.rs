//! Authorization Process
//! 1. Client gets a random challenge from the server
//! 2. Client encrypts the random challenge in a message and sends it back to the server POST /authenticate
//! 3. Server decrypts the message and verifies the challenge
//! 4. If the challenge is correct, the server sends two JWT tokens to the client (access and refresh tokens)
//! 5. Client uses the access token to access protected services
//! 6. If the access token expires, the client uses the refresh token to get a new access token

use super::message_inbound::InboundMessage;
use crate::{
    common::errors::{AppError, MediatorError, SuccessResponse},
    database::session::{Session, SessionClaims, SessionState},
    SharedData,
};
use affinidi_messaging_didcomm::{envelope::MetaEnvelope, Message, UnpackOptions};
use affinidi_messaging_sdk::messages::{known::MessageType, GenericDataStruct};
use axum::{extract::State, Json};
use http::StatusCode;
use jsonwebtoken::{encode, Header};
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use sha256::digest;
use std::time::SystemTime;
use tracing::{debug, info, warn};

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct AuthenticationChallenge {
    pub challenge: String,
    pub session_id: String,
}
impl GenericDataStruct for AuthenticationChallenge {}

/// Request body for POST /authenticate/challenge
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct ChallengeBody {
    pub did: String,
}

/// POST /authenticate/challenge
/// Request from client to get the challenge
/// This is the first step in the authentication process
/// Creates a new sessionID and a random challenge string to the client
pub async fn authentication_challenge(
    // ConnectInfo(connect_info): ConnectInfo<SocketAddr>,
    State(state): State<SharedData>,
    Json(body): Json<ChallengeBody>,
) -> Result<(StatusCode, Json<SuccessResponse<AuthenticationChallenge>>), AppError> {
    let session = Session {
        session_id: create_random_string(12),
        challenge: create_random_string(32),
        state: SessionState::ChallengeSent,
        did: body.did.clone(),
    };

    state.database.create_session(&session).await?;

    debug!(
        "{}: Challenge sent to DID({})",
        session.session_id, session.did
    );

    Ok((
        StatusCode::OK,
        Json(SuccessResponse {
            sessionId: session.session_id.clone(),
            httpCode: StatusCode::OK.as_u16(),
            errorCode: 0,
            errorCodeStr: "NA".to_string(),
            message: "Success".to_string(),
            data: Some(AuthenticationChallenge {
                challenge: session.challenge,
                session_id: session.session_id.clone(),
            }),
        }),
    ))
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct AuthorizationResponse {
    pub access_token: String,
    pub refresh_token: String,
}
impl GenericDataStruct for AuthorizationResponse {}

/// POST /authenticate
/// Response from client to the challenge
/// Unpack the message (only accepts Affinidi Authenticate Protocol)
/// Retrieve Session data from database
/// Check that the DID matches from the message to the session DID recorded
pub async fn authentication_response(
    State(state): State<SharedData>,
    Json(body): Json<InboundMessage>,
) -> Result<(StatusCode, Json<SuccessResponse<AuthorizationResponse>>), AppError> {
    let s = serde_json::to_string(&body).unwrap();

    let mut envelope = match MetaEnvelope::new(
        &s,
        &state.did_resolver,
        &state.config.security.mediator_secrets,
    )
    .await
    {
        Ok(envelope) => envelope,
        Err(e) => {
            return Err(MediatorError::ParseError(
                "UNKNOWN".to_string(),
                "Raw inbound DIDComm message".into(),
                e.to_string(),
            )
            .into());
        }
    };

    // Unpack the message
    let (msg, _) = match Message::unpack(
        &mut envelope,
        &state.did_resolver,
        &state.config.security.mediator_secrets,
        &UnpackOptions::default(),
    )
    .await
    {
        Ok(ok) => ok,
        Err(e) => {
            return Err(MediatorError::MessageUnpackError(
                "UNKNOWN".to_string(),
                format!("Couldn't unpack incoming message. Reason: {}", e),
            )
            .into());
        }
    };

    // Only accepts AffinidiAuthenticate messages
    match msg.type_.as_str().parse::<MessageType>().map_err(|err| {
        MediatorError::ParseError("UNKNOWN".to_string(), "msg.type".into(), err.to_string())
    })? {
        MessageType::AffinidiAuthenticate => (),
        _ => {
            return Err(MediatorError::SessionError(
                "UNKNOWN".to_string(),
                "Only accepts Affinidi Authentication protocol messages".to_string(),
            )
            .into())
        }
    }

    // Ensure the message hasn't expired
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    if let Some(expires) = msg.expires_time {
        if expires <= now {
            return Err(MediatorError::MessageExpired(
                "-1".into(),
                expires.to_string(),
                now.to_string(),
            )
            .into());
        }
    }

    // Turn message body into Challenge
    let challenge: AuthenticationChallenge = serde_json::from_value(msg.body).map_err(|err| {
        warn!("Couldn't parse body into ChallengeBody. Reason: {}", err);
        MediatorError::SessionError(
            "UNKNOWN".into(),
            format!("Couldn't parse body into ChallengeBody. Reason: {}", err),
        )
    })?;

    // Retrieve the session info from the database
    let mut session = state.database.get_session(&challenge.session_id).await?;

    // check that the DID matches from what was given for the initial challenge request to what was used for the message response
    if let Some(from_did) = msg.from {
        if from_did != session.did {
            warn!(
                "DID ({}) from authorization message does not match DID ({}) from session",
                from_did, session.did
            );
            return Err(MediatorError::SessionError(
                challenge.session_id.clone(),
                format!(
                    "DID ({}) from authorization message does not match DID from session",
                    from_did
                ),
            )
            .into());
        }
    }

    // Check that this isn't a replay attack
    if let SessionState::ChallengeSent = session.state {
        debug!("Database session state is ChallengeSent - Good to go!");
    } else {
        warn!(
            "{}: Session is in an invalid state for authentication",
            session.session_id
        );
        return Err(MediatorError::SessionError(
            session.session_id.clone(),
            "Session is in an invalid state for authentication".into(),
        )
        .into());
    }
    let old_sid = session.session_id;
    session.session_id = create_random_string(12);

    // Passed all the checks, now create the JWT tokens
    let access_claims = SessionClaims {
        aud: "ATM".to_string(),
        sub: session.did.clone(),
        session_id: session.session_id.clone(),
        exp: (SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 900),
    };
    // refresh token expires in 24 hours (86,400 seconds - 900 (15 minutes) = 85,500 seconds)
    let mut refresh_claims = access_claims.clone();
    refresh_claims.exp += 85500;

    let response = AuthorizationResponse {
        access_token: encode(
            &Header::new(jsonwebtoken::Algorithm::EdDSA),
            &access_claims,
            &state.config.security.jwt_encoding_key,
        )
        .map_err(|err| {
            MediatorError::InternalError(
                "UNKNOWN".into(),
                format!("Couldn't encode access token. Reason: {}", err),
            )
        })?,
        refresh_token: encode(
            &Header::new(jsonwebtoken::Algorithm::EdDSA),
            &refresh_claims,
            &state.config.security.jwt_encoding_key,
        )
        .map_err(|err| {
            MediatorError::InternalError(
                "UNKNOWN".into(),
                format!("Couldn't encode refresh token. Reason: {}", err),
            )
        })?,
    };

    // Set the session state to Authorized
    state
        .database
        .update_session_authenticated(&old_sid, &session.session_id, &digest(&session.did))
        .await?;

    info!(
        "{}: Authentication successful for DID({})",
        session.session_id, session.did
    );

    Ok((
        StatusCode::OK,
        Json(SuccessResponse {
            sessionId: session.session_id.clone(),
            httpCode: StatusCode::OK.as_u16(),
            errorCode: 0,
            errorCodeStr: "NA".to_string(),
            message: "Success".to_string(),
            data: Some(response),
        }),
    ))
}

/// creates a random string of up to length characters
fn create_random_string(length: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}
