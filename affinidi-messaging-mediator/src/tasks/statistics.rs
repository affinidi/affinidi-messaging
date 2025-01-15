use std::time::Duration;

use tracing::{debug, info, span, Instrument, Level};

use crate::{
    common::errors::MediatorError,
    database::{stats::MetadataStats, DatabaseHandler},
};

/// Periodically logs statistics about the database.
/// Is spawned as a task from main().
pub async fn statistics(database: DatabaseHandler) -> Result<(), MediatorError> {
    let _span = span!(Level::INFO, "statistics");

    async move {
        debug!("Starting statistics thread...");
        let mut interval = tokio::time::interval(Duration::from_secs(60));

        let mut previous_stats = MetadataStats::default();

        loop {
            interval.tick().await;
            let stats = database.get_db_metadata().await?;
            let delta = stats.delta(&previous_stats);
            info!(event_type="UpdateStats",
                  received_bytes=stats.received_bytes,
                  sent_bytes=stats.sent_bytes,
                  deleted_bytes=stats.deleted_bytes,
                  received_count=stats.received_count,
                  sent_count=stats.sent_count,
                  deleted_count=stats.deleted_count,
                  websocket_open=stats.websocket_open,
                  websocket_close=stats.websocket_close,
                  sessions_created=stats.sessions_created,
                  sessions_success=stats.sessions_success,
                  oob_invites_created=stats.oob_invites_created,
                  oob_invites_claimed=stats.oob_invites_claimed);

            info!(event_type="UpdateDeltaStats",
                  received_bytes=delta.received_bytes,
                  sent_bytes=delta.sent_bytes,
                  deleted_bytes=delta.deleted_bytes,
                  received_count=delta.received_count,
                  sent_count=delta.sent_count,
                  deleted_count=delta.deleted_count,
                  websocket_open=delta.websocket_open,
                  websocket_close=delta.websocket_close,
                  sessions_created=delta.sessions_created,
                  sessions_success=delta.sessions_success,
                  oob_invites_created=delta.oob_invites_created,
                  oob_invites_claimed=delta.oob_invites_claimed);

            previous_stats = stats;
        }
    }
    .instrument(_span)
    .await
}
