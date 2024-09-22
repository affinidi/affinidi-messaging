use super::DatabaseHandler;
use crate::common::errors::MediatorError;
use itertools::Itertools;
use redis::{from_redis_value, Value};
use std::fmt::{self, Display, Formatter};
use tracing::{debug, event, Level};

/// Statistics for the mediator
#[derive(Default, Debug)]
pub struct MetadataStats {
    pub received_bytes: i64,   // Total number of bytes processed
    pub sent_bytes: i64,       // Total number of bytes sent
    pub deleted_bytes: i64,    // Total number of bytes deleted
    pub received_count: i64,   // Total number of messages received
    pub sent_count: i64,       // Total number of messages sent
    pub deleted_count: i64,    // Total number of messages deleted
    pub websocket_open: i64,   // Total number of websocket connections opened
    pub websocket_close: i64,  // Total number of websocket connections closed
    pub sessions_created: i64, // Total number of sessions created
    pub sessions_success: i64, // Total number of sessions successfully authenticated
}

impl Display for MetadataStats {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"
    Message counts: recv({}) sent({}) deleted({}) queued({})
    Storage: received({}), sent({}), deleted({}), current_queued({})
    Connections: ws_open({}) ws_close({}) ws_current({}) :: sessions_created({}), sessions_authenticated({})
            "#,
            self.received_count,
            self.sent_count,
            self.deleted_count,
            self.received_count - self.deleted_count,
            self.received_bytes,
            self.sent_bytes,
            self.deleted_bytes,
            self.received_bytes - self.deleted_bytes,
            self.websocket_open,
            self.websocket_close,
            self.websocket_open - self.websocket_close,
            self.sessions_created,
            self.sessions_success
        )
    }
}

impl MetadataStats {
    /// Calculate the delta between two MetadataStats
    pub fn delta(&self, previous: &MetadataStats) -> MetadataStats {
        MetadataStats {
            received_bytes: self.received_bytes - previous.received_bytes,
            sent_bytes: self.sent_bytes - previous.sent_bytes,
            deleted_bytes: self.deleted_bytes - previous.deleted_bytes,
            received_count: self.received_count - previous.received_count,
            sent_count: self.sent_count - previous.sent_count,
            deleted_count: self.deleted_count - previous.deleted_count,
            websocket_open: self.websocket_open - previous.websocket_open,
            websocket_close: self.websocket_close - previous.websocket_close,
            sessions_created: self.sessions_created - previous.sessions_created,
            sessions_success: self.sessions_success - previous.sessions_success,
        }
    }
}

/// Statistics for a given DID
#[derive(Default, Debug)]
pub struct DidStats {
    pub send_queue_bytes: u64,
    pub send_queue_count: u64,
    pub receive_queue_bytes: u64,
    pub receive_queue_count: u64,
}

impl DatabaseHandler {
    /// Retrieves metadata statistics that are global to the mediator database
    /// This means it may include more than this mediator's messages
    pub async fn get_db_metadata(&self) -> Result<MetadataStats, MediatorError> {
        let mut conn = self.get_async_connection().await?;

        let mut stats = MetadataStats::default();

        let result: Value = deadpool_redis::redis::cmd("HGETALL")
            .arg("GLOBAL")
            .query_async(&mut conn)
            .await
            .map_err(|err| {
                event!(
                    Level::ERROR,
                    "Couldn't get shared METADATA from database: {}",
                    err
                );
                MediatorError::DatabaseError(
                    "NA".into(),
                    format!("Couldn't get shared METADATA from database: {}", err),
                )
            })?;

        let result: Vec<String> = from_redis_value(&result).map_err(|e| {
            MediatorError::DatabaseError(
                "NA".into(),
                format!("Couldn't parse GLOBAL metadata from database: {}", e),
            )
        })?;
        debug!("Stats: {:?}", result);

        for (k, v) in result.iter().tuples() {
            match k.as_str() {
                "RECEIVED_BYTES" => stats.received_bytes = v.parse().unwrap_or(0),
                "SENT_BYTES" => stats.sent_bytes = v.parse().unwrap_or(0),
                "DELETED_BYTES" => stats.deleted_bytes = v.parse().unwrap_or(0),
                "RECEIVED_COUNT" => stats.received_count = v.parse().unwrap_or(0),
                "SENT_COUNT" => stats.sent_count = v.parse().unwrap_or(0),
                "DELETED_COUNT" => stats.deleted_count = v.parse().unwrap_or(0),
                "WEBSOCKET_OPEN" => stats.websocket_open = v.parse().unwrap_or(0),
                "WEBSOCKET_CLOSE" => stats.websocket_close = v.parse().unwrap_or(0),
                "SESSIONS_CREATED" => stats.sessions_created = v.parse().unwrap_or(0),
                "SESSIONS_SUCCESS" => stats.sessions_success = v.parse().unwrap_or(0),
                _ => {}
            }
        }

        Ok(stats)
    }

    /// Updates GLOBAL send metrics
    pub async fn update_send_stats(&self, sent_bytes: i64) -> Result<(), MediatorError> {
        let mut con = self.get_async_connection().await?;

        deadpool_redis::redis::pipe()
            .atomic()
            .cmd("HINCRBY")
            .arg("GLOBAL")
            .arg("SENT_BYTES")
            .arg(sent_bytes)
            .cmd("HINCRBY")
            .arg("SENT_COUNT")
            .arg(1)
            .query_async(&mut con)
            .await
            .map_err(|err| {
                MediatorError::DatabaseError(
                    "INTERNAL".into(),
                    format!("Couldn't update GLOBAL SEND stats. Reason: {}", err),
                )
            })?;

        Ok(())
    }

    /// Increment WebSocket open count
    pub async fn global_stats_increment_websocket_open(&self) -> Result<(), MediatorError> {
        let mut con = self.get_async_connection().await?;

        deadpool_redis::redis::cmd("HINCRBY")
            .arg("GLOBAL")
            .arg("WEBSOCKET_OPEN")
            .arg(1)
            .query_async(&mut con)
            .await
            .map_err(|err| {
                MediatorError::DatabaseError(
                    "INTERNAL".into(),
                    format!(
                        "Couldn't update GLOBAL(WEBSOCKET_OPEN) stats. Reason: {}",
                        err
                    ),
                )
            })?;

        Ok(())
    }

    /// Increment WebSocket close count
    pub async fn global_stats_increment_websocket_close(&self) -> Result<(), MediatorError> {
        let mut con = self.get_async_connection().await?;

        deadpool_redis::redis::cmd("HINCRBY")
            .arg("GLOBAL")
            .arg("WEBSOCKET_CLOSE")
            .arg(1)
            .query_async(&mut con)
            .await
            .map_err(|err| {
                MediatorError::DatabaseError(
                    "INTERNAL".into(),
                    format!(
                        "Couldn't update GLOBAL(WEBSOCKET_CLOSE) stats. Reason: {}",
                        err
                    ),
                )
            })?;

        Ok(())
    }

    /// Get stats relating to a DID
    /// - `did_hash` - The hash of the DID to get stats for
    pub async fn get_did_stats(&self, did_hash: &str) -> Result<DidStats, MediatorError> {
        let mut con = self.get_async_connection().await?;

        let result: Value = deadpool_redis::redis::cmd("HGETALL")
            .arg(["DID", did_hash].join(":"))
            .query_async(&mut con)
            .await
            .map_err(|err| {
                MediatorError::DatabaseError(
                    "INTERNAL".into(),
                    format!(
                        "Couldn't retrieve DID ({}) stats. Reason: {}",
                        did_hash, err
                    ),
                )
            })?;

        let mut stats = DidStats::default();
        let result: Vec<String> = from_redis_value(&result).map_err(|e| {
            MediatorError::DatabaseError(
                "NA".into(),
                format!("Couldn't parse GLOBAL metadata from database: {}", e),
            )
        })?;

        for (k, v) in result.iter().tuples() {
            match k.as_str() {
                "SEND_QUEUE_BYTES" => stats.send_queue_bytes = v.parse().unwrap_or(0),
                "SEND_QUEUE_COUNT" => stats.send_queue_count = v.parse().unwrap_or(0),
                "RECEIVE_QUEUE_BYTES" => stats.receive_queue_bytes = v.parse().unwrap_or(0),
                "RECEIVE_QUEUE_COUNT" => stats.receive_queue_count = v.parse().unwrap_or(0),
                _ => {}
            }
        }
        Ok(stats)
    }
}
