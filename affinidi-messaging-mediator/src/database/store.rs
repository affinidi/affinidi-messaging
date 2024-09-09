use super::DatabaseHandler;
use crate::common::errors::MediatorError;
use serde::{Deserialize, Serialize};
use sha256::digest;
use tracing::{debug, event, span, Instrument, Level};

#[derive(Serialize, Deserialize, Debug)]
pub struct MessageMetaData {
    pub bytes: usize,
    pub to_did_hash: String,
    pub from_did_hash: Option<String>,
    pub timestamp: u128,
}

impl DatabaseHandler {
    /// Stores a message in the database
    /// Returns the message_id (hash of the message)
    pub async fn store_message(
        &self,
        session_id: &str,
        message: &str,
        to_did: &str,
        from_did: Option<&str>,
    ) -> Result<String, MediatorError> {
        let _span = span!(Level::DEBUG, "store_message", session_id = session_id);
        async move {
            let message_hash = digest(message.as_bytes());
            let to_hash = digest(to_did.as_bytes());

            let mut conn = self.get_async_connection().await?;
            let mut tx = deadpool_redis::redis::cmd("FCALL");

            tx.arg("store_message")
                .arg(1)
                .arg(&message_hash)
                .arg(message)
                .arg(message.len())
                .arg(to_did)
                .arg(&to_hash);

            if let Some(from_did) = from_did {
                let from_hash = digest(from_did.as_bytes());
                tx.arg(from_did).arg(from_hash);
            } else {
                tx.arg("ANONYMOUS");
            }

            debug!(
                "trying to store msg_id({}), from({:?}) from_hash({:?}) to({}) to_hash({}), bytes({})",
                message_hash,
                from_did,
                from_did.map(|h| digest(h.as_bytes())),
                to_did,
                &to_hash,
                message.len()
            );

            let result: String = tx.query_async(&mut conn).await.map_err(|err| {
                event!(Level::ERROR, "Couldn't store message in database: {}", err);
                MediatorError::DatabaseError(
                    session_id.into(),
                    format!("Couldn't store message in database: {}", err),
                )
            })?;

            debug!("result = {:?}", result);

            debug!("Message hash({}) stored in database", message_hash);

            Ok(message_hash)
        }
        .instrument(_span)
        .await
    }

    /// Retrieves the message MetaData for a given message hash
    /// - session_id: The session_id for the request
    /// - message_hash: The hash of the message to retrieve
    pub async fn get_message_metadata(
        &self,
        session_id: &str,
        message_hash: &str,
    ) -> Result<MessageMetaData, MediatorError> {
        let _span = span!(
            Level::DEBUG,
            "get_message_metadata",
            session_id = session_id,
            message_hash = message_hash
        );
        async move {
            let mut conn = self.get_async_connection().await?;
            let metadata: String = deadpool_redis::redis::cmd("HGET")
                .arg("MESSAGE_STORE")
                .arg(["METADATA:", message_hash].concat())
                .query_async(&mut conn)
                .await
                .map_err(|err| {
                    event!(
                        Level::ERROR,
                        "Couldn't get message metadata from database: {}",
                        err
                    );
                    MediatorError::DatabaseError(
                        session_id.into(),
                        format!("Couldn't get message metadata from database: {}", err),
                    )
                })?;

            let metadata: MessageMetaData = serde_json::from_str(&metadata).map_err(|err| {
                event!(
                    Level::ERROR,
                    "Couldn't parse message metadata from database: {}",
                    err
                );
                MediatorError::DatabaseError(
                    session_id.into(),
                    format!("Couldn't parse message metadata from database: {}", err),
                )
            })?;

            Ok(metadata)
        }
        .instrument(_span)
        .await
    }
}
