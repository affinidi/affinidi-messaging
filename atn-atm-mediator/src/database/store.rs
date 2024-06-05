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
    /// Step 1: Create a transaction
    /// Step 2: Store the message in the MESSAGE_STORE
    /// Step 3: Increment the MESSAGE_STORE bytes_stored field
    /// Step 4: Store the sender in the SEND_Q_<DID_HASH> LIST (this may not be required if anonymous sender)
    /// Step 5: Update DID_<hash> for sender stats
    /// Step 6: Create a pointer in the EXPIRY_LIST List
    /// Step 7: Update DID_<hash> for recipient stats
    /// Step 8: Update DID_LIST (Hash) for mapping of DID/hash values
    /// Step 9: Create a pointer in the RECEIVE_Q_<DID_HASH> Stream
    /// step 10: Create Metadata record for the message (bytes, to_did_hash, from_did_hash, timestamp)
    /// Step 11: Commit the transaction
    pub async fn store_message(
        &self,
        session_id: &str,
        message: &str,
        to_did: &str,
        from_did: Option<&str>,
    ) -> Result<(), MediatorError> {
        let _span = span!(Level::DEBUG, "store_message", session_id = session_id);
        async move {
            let message_hash = digest(message.as_bytes());
            let to_hash = digest(to_did.as_bytes());

            let mut conn = self.get_connection().await?;
            let mut tx = deadpool_redis::redis::cmd("FCALL");

            tx.arg("store_message")
                .arg(1)
                .arg(&message_hash)
                .arg(message)
                .arg(message.len())
                .arg(to_did)
                .arg(to_hash);

            if let Some(from_did) = from_did {
                let from_hash = digest(from_did.as_bytes());
                tx.arg(from_did).arg(from_hash);
            } else {
                tx.arg("ANONYMOUS");
            }
            let result: String = tx.query_async(&mut conn).await.map_err(|err| {
                event!(Level::ERROR, "Couldn't store message in database: {}", err);
                MediatorError::DatabaseError(
                    session_id.into(),
                    format!("Couldn't store message in database: {}", err),
                )
            })?;

            debug!("result = {:?}", result);

            debug!("Message hash({}) stored in database", message_hash);

            Ok(())
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
            let mut conn = self.get_connection().await?;
            let metadata: String = deadpool_redis::redis::cmd("HGET")
                .arg("MESSAGE_STORE")
                .arg(&["METADATA:", message_hash].concat())
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
