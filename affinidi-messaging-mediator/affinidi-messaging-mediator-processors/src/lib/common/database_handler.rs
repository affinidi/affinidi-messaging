use deadpool_redis::Connection;
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use std::{thread::sleep, time::Duration};
use tracing::{error, event, info, Level};

use super::error::ProcessorError;

const REDIS_VERSION_REQ: &str = ">=7.1, <8.0";

/// Used for configuration options for the database
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub database_url: String,
    pub database_pool_size: usize,
    pub database_timeout: u64,
}

#[derive(Clone)]
pub struct DatabaseHandler {
    pub pool: deadpool_redis::Pool,
}

impl DatabaseHandler {
    pub fn from_pool(pool: deadpool_redis::Pool) -> Self {
        Self { pool }
    }

    pub async fn new(config: &DatabaseConfig) -> Result<Self, ProcessorError> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        // Creates initial pool Configuration from the redis database URL
        let pool = deadpool_redis::Config::from_url(&config.database_url)
            .builder()
            .map_err(|err| {
                event!(Level::ERROR, "Database URL is invalid. Reason: {}", err);
                ProcessorError::MessageExpiryCleanupError(format!(
                    "Database URL is invalid. Reason: {}",
                    err
                ))
            })?;

        // Now that we have a base config, we customise the redis pool config
        // and create the async pool of redis connections
        let pool = pool
            .runtime(deadpool_redis::Runtime::Tokio1)
            .max_size(config.database_pool_size)
            .timeouts(deadpool_redis::Timeouts {
                wait: Some(Duration::from_secs(config.database_timeout)),
                create: Some(Duration::from_secs(config.database_timeout)),
                recycle: Some(Duration::from_secs(config.database_timeout)),
            })
            .build()
            .map_err(|err| {
                event!(Level::ERROR, "Database config is invalid. Reason: {}", err);
                ProcessorError::MessageExpiryCleanupError(format!(
                    "Database config is invalid. Reason: {}",
                    err
                ))
            })?;

        let database = Self { pool };
        loop {
            let mut conn = match database.get_async_connection().await {
                Ok(conn) => conn,
                Err(err) => {
                    event!(Level::WARN, "Error getting connection to database: {}", err);
                    event!(Level::WARN, "Retrying database connection in 10 seconds");
                    sleep(Duration::from_secs(10));
                    continue;
                }
            };

            let pong: Result<String, deadpool_redis::redis::RedisError> =
                deadpool_redis::redis::cmd("PING")
                    .query_async(&mut conn)
                    .await;
            match pong {
                Ok(pong) => {
                    event!(
                        Level::INFO,
                        "Database ping ok! Expected (PONG) received ({})",
                        pong
                    );
                    break;
                }
                Err(err) => {
                    event!(
                        Level::WARN,
                        "Can't get connection to database. Reason: {}",
                        err
                    );
                    event!(Level::WARN, "Retrying database connection in 10 seconds");
                    sleep(Duration::from_secs(10));
                }
            }
        }

        // Check the version of Redis Server
        _check_server_version(&database).await?;

        Ok(database)
    }

    /// Returns a redis async database connector or returns an Error
    /// This is the main method to get a connection to the database
    pub async fn get_async_connection(&self) -> Result<Connection, ProcessorError> {
        self.pool.get().await.map_err(|err| {
            event!(Level::ERROR, "Couldn't get database connection: {}", err);
            ProcessorError::MessageExpiryCleanupError(format!(
                "Couldn't get database connection: {}",
                err
            ))
        })
    }
}

/// Helper function to check the version of the Redis Server
async fn _check_server_version(database: &DatabaseHandler) -> Result<String, ProcessorError> {
    let redis_version_req: VersionReq = match VersionReq::parse(REDIS_VERSION_REQ) {
        Ok(result) => result,
        Err(err) => panic!("Couldn't process required Redis version. Reason: {}", err),
    };

    let mut conn = database.get_async_connection().await?;
    let server_info: String = match deadpool_redis::redis::cmd("INFO")
        .arg("SERVER")
        .query_async(&mut conn)
        .await
    {
        Ok(result) => result,
        Err(err) => {
            return Err(ProcessorError::MessageExpiryCleanupError(format!(
                "Couldn't get server info. Reason: {}",
                err
            )));
        }
    };

    let server_version = server_info
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split(":").collect();
            if parts.len() == 2 {
                if parts[0] == "redis_version" {
                    Some(parts[1].to_owned())
                } else {
                    None
                }
            } else {
                None
            }
        })
        .next();

    if let Some(version) = server_version {
        let semver_version: Version = match Version::parse(&version) {
            Ok(result) => result,
            Err(err) => {
                error!("Cannot parse Redis version ({}). Reason: {}", version, err);
                return Err(ProcessorError::MessageExpiryCleanupError(format!(
                    "Cannot parse Redis version ({}). Reason: {}",
                    version, err
                )));
            }
        };
        if redis_version_req.matches(&semver_version) {
            info!("Redis version is compatible: {}", version);
            Ok(version.to_owned())
        } else {
            error!(
                "Redis version ({}) must match ({})",
                version, REDIS_VERSION_REQ
            );
            Err(ProcessorError::MessageExpiryCleanupError(format!(
                "Redis version ({}) must match ({})",
                version, REDIS_VERSION_REQ
            )))
        }
    } else {
        error!("Couldn't find redis_version in server info",);
        Err(ProcessorError::MessageExpiryCleanupError(
            "Couldn't find redis_version in server info".into(),
        ))
    }
}
