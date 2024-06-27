use std::time::Duration;

use tracing::{debug, info, span, Instrument, Level};

use super::errors::MediatorError;
use crate::database::{stats::MetadataStats, DatabaseHandler};

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
            info!("Statistics: {}", stats);
            info!("Delta: {}", stats.delta(&previous_stats));

            previous_stats = stats;
        }
    }
    .instrument(_span)
    .await
}
