use std::time::Duration;

use tracing::{debug, info, span, Instrument, Level};

use super::errors::MediatorError;
use crate::database::DatabaseHandler;

pub async fn statistics(database: DatabaseHandler) -> Result<(), MediatorError> {
    let _span = span!(Level::INFO, "statistics");

    async move {
        debug!("Starting statistics thread...");
        let mut interval = tokio::time::interval(Duration::from_secs(60));

        loop {
            interval.tick().await;
            let stats = database.get_db_metadata().await?;
            info!("Statistics: {:?}", stats);
        }
    }
    .instrument(_span)
    .await
}
