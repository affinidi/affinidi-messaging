use super::DatabaseHandler;
use crate::common::errors::MediatorError;
use tracing::{debug, event, span, Instrument, Level};

impl DatabaseHandler {
    /// Deletes a message in the database
    /// - session_id: authentication session ID
    /// - did: DID of the delete requestor
    /// - message_hash: sha257 hash of the message to delete
    pub async fn delete_message(
        &self,
        session_id: &str,
        did_hash: &str,
        message_hash: &str,
    ) -> Result<(), MediatorError> {
        let _span = span!(
            Level::DEBUG,
            "delete_message",
            message_hash = message_hash,
            did_hash = did_hash
        );
        async move {
            let mut conn = self.get_async_connection().await?;
            let response: String = deadpool_redis::redis::cmd("FCALL")
                .arg("delete_message")
                .arg(1)
                .arg(message_hash)
                .arg(did_hash)
                .query_async(&mut conn)
                .await
                .map_err(|err| {
                    event!(
                        Level::ERROR,
                        "Couldn't delete message_id({}) from database for DID {}: {}",
                        message_hash,
                        did_hash,
                        err
                    );
                    MediatorError::DatabaseError(
                        did_hash.into(),
                        format!(
                            "Couldn't delete message_id({}) from database for DID {}: {}",
                            message_hash, did_hash, err
                        ),
                    )
                })?;

            debug!("database response: ({})", response);

            if response != "OK" {
                Err(MediatorError::DatabaseError(session_id.into(), response))
            } else {
                Ok(())
            }
        }
        .instrument(_span)
        .await
    }
}
