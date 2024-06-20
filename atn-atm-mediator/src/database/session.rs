use std::{
    collections::HashMap,
    fmt::{self, Display, Formatter},
};

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::common::errors::MediatorError;

use super::DatabaseHandler;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionClaims {
    pub aud: String, //audience (atm)
    pub sub: String, // subject (DID)
    pub session_id: String,
    pub exp: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub enum SessionState {
    #[default]
    Unknown,
    ChallengeSent,
    Authenticated,
    Blocked,
}

impl TryFrom<&String> for SessionState {
    type Error = MediatorError;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "ChallengeSent" => Ok(Self::ChallengeSent),
            "Authenticated" => Ok(Self::Authenticated),
            _ => {
                warn!("Unknown SessionState: ({})", value);
                Err(MediatorError::SessionError(
                    "NA".into(),
                    format!("Unknown SessionState: ({})", value),
                ))
            }
        }
    }
}

impl Display for SessionState {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Session {
    #[serde(skip)]
    pub session_id: String,
    pub challenge: String,
    pub remote_address: String,
    pub state: SessionState,
    pub did: String,
}

impl TryFrom<(&str, HashMap<String, String>)> for Session {
    type Error = MediatorError;

    fn try_from(value: (&str, HashMap<String, String>)) -> Result<Self, Self::Error> {
        let mut session: Session = Session::default();
        let (sid, hash) = value;
        session.session_id = sid.into();

        if let Some(challenge) = hash.get("challenge") {
            session.challenge.clone_from(challenge);
        } else {
            warn!(
                "{}: No challenge found when retrieving session({})!",
                sid, sid
            );
            return Err(MediatorError::SessionError(
                sid.into(),
                "No challenge found when retrieving session!".into(),
            ));
        }

        if let Some(remote_address) = hash.get("remote_address") {
            session.remote_address.clone_from(remote_address);
        } else {
            warn!(
                "{}: No remote_address found when retrieving session({})!",
                sid, sid
            );
            return Err(MediatorError::SessionError(
                sid.into(),
                "No remote_address found when retrieving session!".into(),
            ));
        }

        if let Some(state) = hash.get("state") {
            session.state = state.try_into()?;
        } else {
            warn!("{}: No state found when retrieving session({})!", sid, sid);
            return Err(MediatorError::SessionError(
                sid.into(),
                "No state found when retrieving session!".into(),
            ));
        }

        if let Some(did) = hash.get("did") {
            session.did = did.into();
        } else {
            warn!("{}: No DID found when retrieving session({})!", sid, sid);
            return Err(MediatorError::SessionError(
                sid.into(),
                "No DID found when retrieving session!".into(),
            ));
        }

        Ok(session)
    }
}

impl DatabaseHandler {
    /// Creates a new session in the database
    /// Typically called when sending the initial challenge to the client
    pub async fn create_session(&self, session: &Session) -> Result<(), MediatorError> {
        let mut con = self.get_connection().await?;

        let sid = format!("SESSION:{}", session.session_id);

        deadpool_redis::redis::pipe()
            .atomic()
            .cmd("HSET")
            .arg(&sid)
            .arg("challenge")
            .arg(&session.challenge)
            .arg("remote_address")
            .arg(&session.remote_address)
            .arg("state")
            .arg(session.state.to_string())
            .arg("did")
            .arg(&session.did)
            .cmd("HINCRBY")
            .arg("GLOBAL")
            .arg("SESSIONS_CREATED")
            .arg(1)
            .expire(&sid, 900)
            .query_async(&mut con)
            .await
            .map_err(|err| {
                MediatorError::SessionError(
                    sid.clone(),
                    format!("tried to create new session ({})! Error: {}", sid, err),
                )
            })?;

        debug!("Session created: {:?}", session);

        Ok(())
    }

    /// Retrieves a session from the database
    pub async fn get_session(&self, session_id: &str) -> Result<Session, MediatorError> {
        let mut con = self.get_connection().await?;

        let result: HashMap<String, String> = deadpool_redis::redis::cmd("HGETALL")
            .arg(format!("SESSION:{}", session_id))
            .query_async(&mut con)
            .await
            .map_err(|err| {
                MediatorError::SessionError(
                    session_id.into(),
                    format!("tried to retrieve session({}). Error: {}", session_id, err),
                )
            })?;

        (session_id, result).try_into()
    }

    /// Updates a session in the database to become authenticated
    /// Updates the state, and the expiry time
    pub async fn update_session_authenticated(
        &self,
        session_id: &str,
    ) -> Result<(), MediatorError> {
        let mut con = self.get_connection().await?;

        let sid = format!("SESSION:{}", session_id);

        deadpool_redis::redis::pipe()
            .atomic()
            .cmd("HSET")
            .arg(&sid)
            .arg("state")
            .arg(SessionState::Authenticated.to_string())
            .cmd("HINCRBY")
            .arg("GLOBAL")
            .arg("SESSIONS_SUCCESS")
            .arg(1)
            .expire(&sid, 86400)
            .query_async(&mut con)
            .await
            .map_err(|err| {
                MediatorError::SessionError(
                    session_id.into(),
                    format!("tried to retrieve session({}). Error: {}", session_id, err),
                )
            })?;

        Ok(())
    }
}
