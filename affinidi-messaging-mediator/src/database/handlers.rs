use super::DatabaseHandler;
use crate::common::{config::Config, errors::MediatorError};
use deadpool_redis::Connection;
use redis::aio::PubSub;
use std::{thread::sleep, time::Duration};
use tracing::{error, event, info, Level};

const LUA_SCRIPTS: &str = "atm-functions.lua";
const REDIS_VERSION: &str = "7.4"; // Minimum Redis version required

impl DatabaseHandler {
    pub async fn new(config: &Config) -> Result<Self, MediatorError> {
        // Creates initial pool Configuration from the redis database URL
        let pool = deadpool_redis::Config::from_url(&config.database_url)
            .builder()
            .map_err(|err| {
                event!(Level::ERROR, "Database URL is invalid. Reason: {}", err);
                MediatorError::DatabaseError(
                    "NA".into(),
                    format!("Database URL is invalid. Reason: {}", err),
                )
            })?;

        // Now that we have a base config, we customise the redis pool config
        // and create the async pool of redis connections
        let pool = pool
            .runtime(deadpool_redis::Runtime::Tokio1)
            .max_size(config.database_pool_size)
            .timeouts(deadpool_redis::Timeouts {
                wait: Some(Duration::from_secs(config.database_timeout.into())),
                create: Some(Duration::from_secs(config.database_timeout.into())),
                recycle: Some(Duration::from_secs(config.database_timeout.into())),
            })
            .build()
            .map_err(|err| {
                event!(Level::ERROR, "Database config is invalid. Reason: {}", err);
                MediatorError::DatabaseError(
                    "NA".into(),
                    format!("Database config is invalid. Reason: {}", err),
                )
            })?;

        let database = Self {
            pool,
            redis_url: config.database_url.clone(),
        };
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

        // Check and load LUA scripts as required
        {
            let mut conn = database.get_async_connection().await?;
            let function_load: Result<String, deadpool_redis::redis::RedisError> =
                deadpool_redis::redis::cmd("FUNCTION")
                    .arg("LOAD")
                    .arg("REPLACE")
                    .arg(LUA_SCRIPTS)
                    .query_async(&mut conn)
                    .await;
            match function_load {
                Ok(function_load) => {
                    event!(
                        Level::INFO,
                        "database response for FUNCTION LOAD: ({})",
                        function_load
                    );
                }
                Err(err) => {
                    event!(
                        Level::WARN,
                        "database response for FUNCTION LOAD: ({})",
                        err
                    );
                }
            }
        }

        database.get_db_metadata().await?;
        Ok(database)
    }

    /// Returns a redis async database connector or returns an Error
    /// This is the main method to get a connection to the database
    pub async fn get_async_connection(&self) -> Result<Connection, MediatorError> {
        self.pool.get().await.map_err(|err| {
            event!(Level::ERROR, "Couldn't get database connection: {}", err);
            MediatorError::DatabaseError(
                "NA".into(),
                format!("Couldn't get database connection: {}", err),
            )
        })
    }

    /// Returns a redis database connector or returns an Error
    /// This should only be used for pubsub operations
    pub async fn get_pubsub_connection(&self) -> Result<PubSub, MediatorError> {
        let client = redis::Client::open(self.redis_url.clone()).map_err(|err| {
            MediatorError::DatabaseError(
                "NA".into(),
                format!("Couldn't open redis pubsub connection. Reason: {}", err),
            )
        })?;

        client.get_async_pubsub().await.map_err(|err| {
            MediatorError::DatabaseError(
                "NA".into(),
                format!("Couldn't get redis pubsub connection. Reason: {}", err),
            )
        })
    }
}

/// Helper function to check the version of the Redis Server
async fn _check_server_version(database: &DatabaseHandler) -> Result<String, MediatorError> {
    let mut conn = database.get_async_connection().await?;
    let server_info: String = match deadpool_redis::redis::cmd("INFO")
        .arg("SERVER")
        .query_async(&mut conn)
        .await
    {
        Ok(result) => result,
        Err(err) => {
            return Err(MediatorError::DatabaseError(
                "NA".into(),
                format!("Couldn't get server info. Reason: {}", err),
            ));
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
        if version.starts_with(REDIS_VERSION) {
            info!("Redis version is compatible: {}", version);
            Ok(version.to_owned())
        } else {
            error!(
                "Redis version ({}) must be equal or higher than minimum ({})",
                version, REDIS_VERSION
            );
            Err(MediatorError::DatabaseError(
                "NA".into(),
                format!(
                    "Redis version ({}) must be equal or higher than minimum ({})",
                    version, REDIS_VERSION
                ),
            ))
        }
    } else {
        error!("Couldn't find redis_version in server info",);
        Err(MediatorError::DatabaseError(
            "NA".into(),
            "Couldn't find redis_version in server info".into(),
        ))
    }
}
