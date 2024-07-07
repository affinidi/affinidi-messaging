use super::DatabaseHandler;
use crate::common::errors::MediatorError;
use deadpool_redis::Connection;
use redis::{from_redis_value, Value};
use serde_json::json;
use tracing::{debug, error, event, Level};

impl DatabaseHandler {
    pub async fn streaming_clean_start(&self, uuid: &str) -> Result<(), MediatorError> {
        let mut conn = self.get_async_connection().await?;

        let response: Vec<Value> = deadpool_redis::redis::pipe()
            .atomic()
            .cmd("FCALL")
            .arg("clean_start_streaming")
            .arg(1)
            .arg(uuid)
            .query_async(&mut conn)
            .await
            .map_err(|err| {
                event!(
                    Level::ERROR,
                    "redis function clean_start_streaming() failed. Reason: {}",
                    err
                );
                MediatorError::DatabaseError(
                    "NA".into(),
                    format!(
                        "redis function clean_start_streaming() failed. Reason: {}",
                        err
                    ),
                )
            })?;

        if let Ok(count) = from_redis_value::<i64>(&response[0]) {
            event!(
                Level::INFO,
                "clean_start_streaming() cleaned {} sessions",
                count
            );
            Ok(())
        } else {
            event!(
                Level::ERROR,
                "clean_start_streaming() failed to parse response: {:?}",
                response
            );
            Err(MediatorError::DatabaseError(
                "NA".into(),
                format!(
                    "redis fn clean_start_streaming() failed. Response ({:?})",
                    response
                ),
            ))
        }
    }

    /// Checks if the given DID hash is live streaming
    /// Returns the streaming service ID that the client is connecting to if the DID hash is live streaming
    pub async fn streaming_is_client_live(&self, did_hash: &str) -> Option<String> {
        let mut conn = if let Ok(conn) = self.get_async_connection().await {
            conn
        } else {
            error!("is_live_streaming(): Failed to get connection to Redis");
            return None;
        };

        match deadpool_redis::redis::cmd("HGET")
            .arg("GLOBAL_STREAMING")
            .arg(did_hash)
            .query_async(&mut conn)
            .await
        {
            Ok(uuid) => uuid,
            Err(err) => {
                event!(
                    Level::ERROR,
                    "check if live_streaming for did_hash({}) failed. Reason: {}",
                    did_hash,
                    err
                );
                None
            }
        }
    }

    /// Publishes a live message to the streaming service
    /// This follows a call to is_live_streaming() to get the streaming service ID if valid
    /// NOTE: There is a chance that a client could close live-streaming between the check and publishing
    ///        Not an issue, as the streaming component will handle this gracefully
    /// NOTE: Why not combine is_live_streaming() and this function into an atomic action?
    ///       While it would be more efficient in some ways, it would also mean pushing the full message to Redis
    ///       on every delivery, as messages get larger this would become less efficient.
    ///       So best compromise is to have the client check if live-streaming is active, then send the message
    pub async fn streaming_publish_message(
        &self,
        did_hash: &str,
        stream_uuid: &str,
        message: &str,
    ) -> Result<(), MediatorError> {
        let mut conn = self.get_async_connection().await?;

        match deadpool_redis::redis::cmd("PUBLISH")
            .arg(["CHANNEL:", stream_uuid].concat())
            .arg(json!({ "did_hash": did_hash, "message": message }).to_string())
            .query_async::<Connection, Value>(&mut conn)
            .await
        {
            Ok(_) => {
                debug!(
                    "published message to channel(CHANNEL:{}) for did_hash({})",
                    stream_uuid, did_hash
                );
                Ok(())
            }
            Err(err) => {
                event!(
                    Level::ERROR,
                    "publish_live_message() for did_hash({}) channel(CHANNEL:{}) failed. Reason: {}",
                    did_hash,
                    stream_uuid,
                    err
                );
                Err(MediatorError::DatabaseError(
                    "NA".into(),
                    format!(
                        "publish_live_message() for did_hash({}) channel(CHANNEL:{}) failed. Reason: {}",
                        did_hash,
                        stream_uuid,
                        err
                    ),
                ))
            }
        }
    }

    /// Adds a client to the live streaming service
    pub async fn streaming_add_client(
        &self,
        did_hash: &str,
        stream_uuid: &str,
    ) -> Result<(), MediatorError> {
        let mut conn = self.get_async_connection().await?;

        match deadpool_redis::redis::pipe()
            .atomic()
            .cmd("SADD")
            .arg(["STREAMING_SESSIONS:", stream_uuid].concat())
            .arg(did_hash)
            .cmd("HSET")
            .arg("GLOBAL_STREAMING")
            .arg(did_hash)
            .arg(stream_uuid)
            .query_async::<Connection, Value>(&mut conn)
            .await
        {
            Ok(_) => {
                debug!(
                    "added did_hash({}) to live streaming service({})",
                    did_hash, stream_uuid
                );

                Ok(())
            }
            Err(err) => {
                event!(
                    Level::ERROR,
                    "streaming_add_client() for did_hash({}) stream_uuid(STREAMING_SESSIONS:{}) failed. Reason: {}",
                    did_hash,
                    stream_uuid,
                    err
                );
                Err(MediatorError::DatabaseError(
                    "NA".into(),
                    format!(
                        "streaming_add_client() for did_hash({}) stream_uuid(STREAMING_SESSIONS:{}) failed. Reason: {}",
                        did_hash,
                        stream_uuid,
                        err
                    ),
                ))
            }
        }
    }

    /// Removes a client from the live streaming service
    pub async fn streaming_remove_client(
        &self,
        did_hash: &str,
        stream_uuid: &str,
    ) -> Result<(), MediatorError> {
        let mut conn = self.get_async_connection().await?;

        match deadpool_redis::redis::pipe()
            .atomic()
            .cmd("SREM")
            .arg(["STREAMING_SESSIONS:", stream_uuid].concat())
            .arg(did_hash)
            .cmd("HDEL")
            .arg("GLOBAL_STREAMING")
            .arg(did_hash)
            .query_async::<Connection, Value>(&mut conn)
            .await
        {
            Ok(_) => {
                debug!(
                    "removed did_hash({}) from live streaming service({})",
                    did_hash, stream_uuid
                );

                Ok(())
            }
            Err(err) => {
                event!(
                Level::ERROR,
                "streaming_remove_client() for did_hash({}) stream_uuid(STREAMING_SESSIONS:{}) failed. Reason: {}",
                did_hash,
                stream_uuid,
                err
            );
                Err(MediatorError::DatabaseError(
                "NA".into(),
                format!(
                    "streaming_remove_client() for did_hash({}) stream_uuid(STREAMING_SESSIONS:{}) failed. Reason: {}",
                    did_hash,
                    stream_uuid,
                    err
                ),
            ))
            }
        }
    }
}
