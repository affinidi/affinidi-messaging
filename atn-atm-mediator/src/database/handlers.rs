use std::{thread::sleep, time::Duration};

use deadpool_redis::Connection;
use redis::{from_redis_value, Value};
use tracing::{debug, event, Level};

use crate::common::{config::Config, errors::MediatorError};

use super::{DatabaseHandler, MetadataStats};

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

        let database = Self { pool };
        loop {
            let mut conn = match database.get_connection().await {
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

        database.get_db_metadata().await?;
        Ok(database)
    }

    /// Returns a redis async database connector or returns an Error
    pub async fn get_connection(&self) -> Result<Connection, MediatorError> {
        self.pool.get().await.map_err(|err| {
            event!(Level::ERROR, "Couldn't get database connection: {}", err);
            MediatorError::DatabaseError(
                "NA".into(),
                format!("Couldn't get database connection: {}", err),
            )
        })
    }

    /// Retrieves metadata statistics that are global to the mediator database
    /// This means it may include more than this mediator's messages
    pub async fn get_db_metadata(&self) -> Result<MetadataStats, MediatorError> {
        let mut conn = self.get_connection().await?;

        let mut stats = MetadataStats::default();

        let result: Value = deadpool_redis::redis::cmd("HMGET")
            .arg("GLOBAL")
            .arg("RECEIVED_BYTES")
            .arg("SENT_BYTES")
            .arg("RECEIVED_COUNT")
            .arg("SENT_COUNT")
            .arg("DELETED_COUNT")
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

        let result: Vec<Value> = from_redis_value(&result).map_err(|e| {
            MediatorError::DatabaseError(
                "NA".into(),
                format!("Couldn't parse GLOBAL metadata from database: {}", e),
            )
        })?;
        debug!("Stats: {:?}", result);

        for (i, item) in result.iter().enumerate() {
            match i {
                0 => stats.received_bytes = from_redis_value(item).unwrap_or(0),
                1 => stats.sent_bytes = from_redis_value(item).unwrap_or(0),
                2 => stats.received_count = from_redis_value(item).unwrap_or(0),
                3 => stats.sent_count = from_redis_value(item).unwrap_or(0),
                4 => stats.deleted_count = from_redis_value(item).unwrap_or(0),
                _ => {}
            }
        }

        Ok(stats)
    }
}
