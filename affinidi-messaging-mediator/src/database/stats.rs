use super::DatabaseHandler;
use crate::common::errors::MediatorError;
use itertools::Itertools;
use num_format::{Locale, ToFormattedString};
use redis::{from_redis_value, Value};
use std::fmt::{self, Display, Formatter};
use tracing::{debug, event, Level};
use serde::{Serialize};
use serde_json::{to_string};

/// Statistics for the mediator
#[derive(Default, Debug)]
pub struct MetadataStats {
    pub received_bytes: u64,      // Total number of bytes processed
    pub sent_bytes: u64,          // Total number of bytes sent
    pub deleted_bytes: u64,       // Total number of bytes deleted
    pub received_count: u64,      // Total number of messages received
    pub sent_count: u64,          // Total number of messages sent
    pub deleted_count: u64,       // Total number of messages deleted
    pub websocket_open: u64,      // Total number of websocket connections opened
    pub websocket_close: u64,     // Total number of websocket connections closed
    pub sessions_created: u64,    // Total number of sessions created
    pub sessions_success: u64,    // Total number of sessions successfully authenticated
    pub oob_invites_created: u64, // Total number of out-of-band invites created
    pub oob_invites_claimed: u64, // Total number of out-of-band invites claimed
    pub event_type: Option<String>, // event_type for analytics
}


#[derive(Serialize)]
struct LogData {
    event_type: String,
    source_project_id: String,
    time_stamp: String,
    payload: Payload,
}

#[derive(Serialize)]
struct Payload {
    message_counts: MessageCounts,
    storage: Storage,
    connections: Connections,
    oob_invites: OobInvites,
}

#[derive(Serialize)]
struct MessageCounts {
    recv: u64,
    sent: u64,
    deleted: u64,
    queued: u64,
}

#[derive(Serialize)]
struct Storage {
    received: u64,
    sent: u64,
    deleted: u64,
    current_queued: u64,
}

#[derive(Serialize)]
struct Connections {
    ws_open: u64,
    ws_close: u64,
    ws_current: u64,
    sessions_created: u64,
    sessions_authenticated: u64,
}

#[derive(Serialize)]
struct OobInvites {
    created: u64,
    claimed: u64,
}

impl Display for MetadataStats {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        // If event_type is Some, use it; otherwise, default to "totalStatistics"
        let event_type = self.event_type.as_deref().unwrap_or("totalStatistics");

        let log_data = LogData {
            event_type: event_type.to_string(),
            source_project_id: "1234-12314-134124455-124414".to_string(), //TODO: Retrieve the projectId dynamically and eliminate the hardcoded string
            time_stamp: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
            payload: Payload {
                message_counts: MessageCounts {
                    recv: self.received_count,
                    sent: self.sent_count,
                    deleted: self.deleted_count,
                    queued: self.received_count - self.deleted_count,
                },
                storage: Storage {
                    received: self.received_bytes,
                    sent: self.sent_bytes,
                    deleted: self.deleted_bytes,
                    current_queued: self.received_bytes - self.deleted_bytes,
                },
                connections: Connections {
                    ws_open: self.websocket_open,
                    ws_close: self.websocket_close,
                    ws_current: (self.websocket_open - self.websocket_close),
                    sessions_created: self.sessions_created,
                    sessions_authenticated: self.sessions_success,
                },
                oob_invites: OobInvites {
                    created: self.oob_invites_created,
                    claimed: self.oob_invites_claimed,
                }
            },
        };
        // Convert the log_data to a JSON string
        let json_output = to_string(&log_data).unwrap();

        // Output the JSON string
        write!(f, "{}", json_output)
    }
}

impl MetadataStats {
    /// Calculate the delta between two MetadataStats
    pub fn delta(&self, previous: &MetadataStats) -> MetadataStats {
        MetadataStats {
            event_type: Some("deltaStatistics".to_string()),
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
            oob_invites_created: self.oob_invites_created - previous.oob_invites_created,
            oob_invites_claimed: self.oob_invites_claimed - previous.oob_invites_claimed,
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
                "OOB_INVITES_CREATED" => stats.oob_invites_created = v.parse().unwrap_or(0),
                "OOB_INVITES_CLAIMED" => stats.oob_invites_claimed = v.parse().unwrap_or(0),
                _ => {}
            }
        }

        Ok(stats)
    }

    /// Updates GLOBAL send metrics
    pub async fn update_send_stats(&self, sent_bytes: i64) -> Result<(), MediatorError> {
        let mut con = self.get_async_connection().await?;

        let _result: Value = deadpool_redis::redis::pipe()
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

        let _result: Value = deadpool_redis::redis::cmd("HINCRBY")
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

        let _result: Value = deadpool_redis::redis::cmd("HINCRBY")
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

    /// Forward Task Queue length
    pub async fn get_forward_tasks_len(&self) -> Result<usize, MediatorError> {
        let mut con = self.get_async_connection().await?;

        let result: usize = deadpool_redis::redis::cmd("XLEN")
            .arg("FORWARD_TASKS")
            .query_async(&mut con)
            .await
            .map_err(|err| {
                MediatorError::DatabaseError(
                    "INTERNAL".into(),
                    format!("Couldn't retrieve forward_tasks length. Reason: {}", err),
                )
            })?;

        Ok(result)
    }
}
