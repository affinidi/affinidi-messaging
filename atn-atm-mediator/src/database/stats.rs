use itertools::Itertools;
use redis::{from_redis_value, Value};
use tracing::{debug, event, Level};

use crate::common::errors::MediatorError;

use super::{DatabaseHandler, MetadataStats};

impl DatabaseHandler {
    /// Retrieves metadata statistics that are global to the mediator database
    /// This means it may include more than this mediator's messages
    pub async fn get_db_metadata(&self) -> Result<MetadataStats, MediatorError> {
        let mut conn = self.get_connection().await?;

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
                _ => {}
            }
        }

        Ok(stats)
    }

    /// Updates GLOBAL send metrics
    pub async fn update_send_stats(&self, sent_bytes: i64) -> Result<(), MediatorError> {
        let mut con = self.get_connection().await?;

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
        let mut con = self.get_connection().await?;

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
        let mut con = self.get_connection().await?;

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
}
