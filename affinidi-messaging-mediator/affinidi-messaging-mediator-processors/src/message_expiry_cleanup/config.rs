// *****************************************************************
// If running the processor separate, then we need some additional
// configuration to run the processor
// *****************************************************************

use affinidi_messaging_processors::{
    common::database_handler::DatabaseConfig,
    message_expiry_cleanup::config::MessageExpiryCleanupConfig,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Config {
    pub database: DatabaseConfig,
    pub processors: ProcessorConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProcessorConfig {
    pub message_expiry_cleanup: MessageExpiryCleanupConfig,
}
