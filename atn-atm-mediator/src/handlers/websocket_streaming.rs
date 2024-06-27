use tracing::{debug, span, Instrument, Level};

use crate::{common::errors::MediatorError, database::DatabaseHandler};

/// Streams messages to subscribed clients over websocket.
/// Is spawned as a task from main().
pub async fn ws_streaming(database: DatabaseHandler, uuid: String) -> Result<(), MediatorError> {
    let _span = span!(Level::INFO, "ws_streaming");

    async move {
        debug!("Starting ws_streaming thread...");

        // Clean up any existing sessions left over from previous runs
        database.clean_start_streaming(&uuid).await?;

        Ok(())
    }
    .instrument(_span)
    .await
}
