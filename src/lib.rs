use chrono::{DateTime, Utc};
use common::{
    config::{read_config_file, Config, ConfigRaw},
    errors::MediatorError,
};
use tracing::{event, level_filters::LevelFilter, Level};
use tracing_subscriber::{reload::Handle, Registry};

pub mod common;
pub mod database;
pub mod handlers;
pub mod resolvers;

#[derive(Clone)]
pub struct SharedData {
    pub config: Config,
    pub service_start_timestamp: DateTime<Utc>,
}

pub async fn init(
    reload_handle: Option<Handle<LevelFilter, Registry>>,
) -> Result<Config, MediatorError> {
    // Read configuration file parameters
    let config = read_config_file("conf/mediator.toml")?;

    // Setup logging
    if reload_handle.is_some() {
        let level: LevelFilter = match config.log_level.as_str() {
            "trace" => LevelFilter::TRACE,
            "debug" => LevelFilter::DEBUG,
            "info" => LevelFilter::INFO,
            "warn" => LevelFilter::WARN,
            "error" => LevelFilter::ERROR,
            _ => {
                event!(
                    Level::WARN,
                    "log_level({}) is unknown in config file. Defaults to INFO",
                    config.log_level
                );
                LevelFilter::INFO
            }
        };
        reload_handle
            .unwrap()
            .modify(|filter| *filter = level)
            .map_err(|e| MediatorError::InternalError("NA".into(), e.to_string()))?;
        event!(Level::INFO, "Log level set to ({})", config.log_level);
    }

    match <common::config::Config as async_convert::TryFrom<ConfigRaw>>::try_from(config).await {
        Ok(config) => {
            event!(
                Level::INFO,
                "Configuration settings parsed successfully.\n{:#?}",
                config
            );
            Ok(config)
        }
        Err(err) => Err(err),
    }
}
