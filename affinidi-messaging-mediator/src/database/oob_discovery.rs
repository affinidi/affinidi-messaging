/*!
 Database operations relating to the storage, retrieval and deletion of OOB Discovery records

 Uses a REDIS Hash to store the OOB Discovery Invitation information

 HASH KEY : OOB_INVITES

 OOB_INVITES Field Naming = OOB_ID
   OOB_ID = SHA256 Hash of the Invite Message
*/

use super::DatabaseHandler;
use crate::common::errors::MediatorError;
use affinidi_messaging_didcomm::Message;
use base64::prelude::*;
use redis::Value;
use sha256::digest;
use std::time::SystemTime;
use tracing::{debug, error, info, span, Instrument, Level};

const HASH_KEY: &str = "OOB_INVITES";

impl DatabaseHandler {
    /// Stores an OOB Discovery Invitation
    /// Will set an expiry on the Invite URL
    pub async fn oob_discovery_store(
        &self,
        did_hash: &str,
        invite: &Message,
    ) -> Result<String, MediatorError> {
        let _span = span!(Level::DEBUG, "oob_discovery_store", did_hash = did_hash);

        async move {
            let mut conn = self.get_async_connection().await?;

            let now = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                Ok(now) => now.as_secs(),
                Err(e) => {
                    error!(
                        "SystemTime::now().duration_since(UNIX_EPOCH) failed! Reason: {}",
                        e
                    );
                    return Err(MediatorError::InternalError(
                        "NA".into(),
                        format!(
                            "SystemTime::now().duration_since(UNIX_EPOCH) failed! Reason: {}",
                            e
                        ),
                    ));
                }
            };

            //TODO: Should add this as a configurable value (Defaults to 24 hours)
            let expire_at = if let Some(expiry) = invite.expires_time {
                if expiry > now + 86_400 {
                    now + 86_400
                } else {
                    expiry
                }
            } else {
                now + 86_400
            };

            let base64_invite = match serde_json::to_string(invite) {
                Ok(msg) => {
                    debug!("invite_str:\n{}", msg);
                    BASE64_URL_SAFE_NO_PAD.encode(msg)
                }
                Err(err) => {
                    error!("serializing error on Message. {}", err);
                    return Err(MediatorError::InternalError(
                        "NA".into(),
                        format!("serializing error on Message. {}", err),
                    ));
                }
            };

            let invite_hash = digest(&base64_invite);

            match deadpool_redis::redis::pipe()
                .atomic()
                .cmd("HSET")
                .arg(HASH_KEY)
                .arg(&invite_hash)
                .arg(&base64_invite)
                .cmd("HEXPIREAT")
                .arg(HASH_KEY)
                .arg(expire_at)
                .arg("FIELDS")
                .arg(1)
                .arg(&invite_hash)
                .cmd("HINCRBY")
                .arg("GLOBAL")
                .arg("OOB_INVITES_CREATED")
                .arg(1)
                .query_async::<Value>(&mut conn)
                .await
            {
                Ok(_) => {
                    info!("OOB Invitation ID({}) created", invite_hash);
                    Ok(invite_hash)
                }
                Err(err) => {
                    error!("Database Error: {}", err);
                    Err(MediatorError::DatabaseError(
                        "NA".into(),
                        format!("database store error: {}", err),
                    ))
                }
            }
        }
        .instrument(_span)
        .await
    }

    /// Retrieve an OOB Discovery Invitation if it exists
    pub async fn oob_discovery_get(&self, oob_id: &str) -> Result<Option<String>, MediatorError> {
        let _span = span!(Level::DEBUG, "oob_discovery_get", oob_id = oob_id);

        async move {
            let mut conn = self.get_async_connection().await?;

            let invitation: Option<String> = match deadpool_redis::redis::pipe()
                .atomic()
                .cmd("HGET")
                .arg(HASH_KEY)
                .arg(oob_id)
                .cmd("HINCRBY")
                .arg("GLOBAL")
                .arg("OOB_INVITES_CLAIMED")
                .arg(1)
                .query_async::<Vec<String>>(&mut conn)
                .await
            {
                Ok(invitation) => invitation.first().map(|a| a.to_string()),
                Err(err) => {
                    error!("Database Error: {}", err);
                    return Err(MediatorError::DatabaseError(
                        "NA".into(),
                        format!("database fetch error: {}", err),
                    ));
                }
            };

            debug!("OOB Discovery Invitation: {:?}", invitation);

            Ok(invitation)
        }
        .instrument(_span)
        .await
    }

    /// Deletes an OOB Discovery Invitation
    pub async fn oob_discovery_delete(&self, oob_id: &str) -> Result<bool, MediatorError> {
        let _span = span!(Level::DEBUG, "oob_discovery_delete", oob_id = oob_id);

        async move {
            let mut conn = self.get_async_connection().await?;

            let result: bool = match deadpool_redis::redis::cmd("HDEL")
                .arg(HASH_KEY)
                .arg(oob_id)
                .query_async::<bool>(&mut conn)
                .await
            {
                Ok(result) => result,
                Err(err) => {
                    error!("Database Error: {}", err);
                    return Err(MediatorError::DatabaseError(
                        "NA".into(),
                        format!("database fetch error: {}", err),
                    ));
                }
            };

            debug!("Delete status: {:?}", result);

            Ok(result)
        }
        .instrument(_span)
        .await
    }
}
