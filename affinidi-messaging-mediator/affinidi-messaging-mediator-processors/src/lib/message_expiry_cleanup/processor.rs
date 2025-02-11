/*!
 * Main task that runs in a loop checking for expired messages and removing them
 */

use std::time::Duration;
use tracing::info;

use crate::common::database_handler::DatabaseHandler;

use super::config::MessageExpiryCleanupConfig;

/// MessageExpiryCleanupProcessor deletes expired messages from the Mediator database
pub struct MessageExpiryCleanupProcessor {
    /// Configuration for the MessageExpiryCleanupProcessor
    config: MessageExpiryCleanupConfig,
    /// Database handler for the Mediator
    pub(crate) database: DatabaseHandler,
}

impl MessageExpiryCleanupProcessor {
    pub fn new(config: MessageExpiryCleanupConfig, database: deadpool_redis::Pool) -> Self {
        MessageExpiryCleanupProcessor {
            config,
            database: DatabaseHandler { pool: database },
        }
    }

    pub async fn start(&self) -> Result<(), crate::common::error::ProcessorError> {
        info!("Expired message cleanup processor started");

        loop {
            let sleep = tokio::time::sleep(Duration::from_secs(1));

            sleep.await;
            let timeslots = self.timeslot_scan().await?;
            for timeslot in timeslots {
                let (expired, total) = self.expire_messages_from_timeslot(&timeslot).await?;
            }
            info!("Timeslots count: {}", timeslots.len());
        }

        // Ok(())
    }
}
