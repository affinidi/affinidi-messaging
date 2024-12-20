use super::DatabaseHandler;
use crate::common::{config::Config, errors::MediatorError};
use deadpool_redis::Connection;
use redis::aio::PubSub;
use semver::{Version, VersionReq};
use std::{fs::read_to_string, thread::sleep, time::Duration};
use tracing::{error, event, info, Level};

const REDIS_VERSION_REQ: &str = ">=7.1, <8.0";

impl DatabaseHandler {
    pub async fn new(config: &Config) -> Result<Self, MediatorError> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        // Creates initial pool Configuration from the redis database URL
        let pool = deadpool_redis::Config::from_url(&config.database.database_url)
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
            .max_size(config.database.database_pool_size)
            .timeouts(deadpool_redis::Timeouts {
                wait: Some(Duration::from_secs(config.database.database_timeout.into())),
                create: Some(Duration::from_secs(config.database.database_timeout.into())),
                recycle: Some(Duration::from_secs(config.database.database_timeout.into())),
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
            redis_url: config.database.database_url.clone(),
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
        _load_scripts(&database, &config.database.functions_file).await?;

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

    let redis_version_req: VersionReq = match VersionReq::parse(REDIS_VERSION_REQ) {
        Ok(result) => result,
        Err(err) => {
            error!("Couldn't process required Redis version. Reason: {}", err);
            return Err(MediatorError::ConfigError(
                "NA".into(),
                format!("Couldn't process required Redis version. Reason: {}", err),
            ));
        }
    };

    if let Some(version) = server_version {
        let semver_version: Version = match Version::parse(&version) {
            Ok(result) => result,
            Err(err) => {
                error!("Cannot parse Redis version ({}). Reason: {}", version, err);
                return Err(MediatorError::DatabaseError(
                    "NA".into(),
                    format!("Cannot parse Redis version ({}). Reason: {}", version, err),
                ));
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
            Err(MediatorError::DatabaseError(
                "NA".into(),
                format!(
                    "Redis version ({}) must match ({})",
                    version, REDIS_VERSION_REQ
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

// Private Helper function to load Redis scripts into the database
async fn _load_scripts(
    database: &DatabaseHandler,
    scripts_path: &str,
) -> Result<(), MediatorError> {
    // Load the file contents into a string
    let lua_scripts = read_to_string(scripts_path).map_err(|err| {
        MediatorError::ConfigError(
            "Initialization".into(),
            format!(
                "Couldn't ready database functions_file ({}). Reason: {}",
                scripts_path, err
            ),
        )
    })?;

    let mut conn = database.get_async_connection().await?;
    match deadpool_redis::redis::cmd("FUNCTION")
        .arg("LOAD")
        .arg("REPLACE")
        .arg(lua_scripts)
        .query_async::<String>(&mut conn)
        .await
    {
        Ok(_) => {
            event!(
                Level::INFO,
                "Loaded LUA scripts into the database from file: {}",
                scripts_path
            );
            Ok(())
        }
        Err(err) => {
            event!(
                Level::WARN,
                "database response for FUNCTION LOAD: ({})",
                err
            );
            Err(MediatorError::DatabaseError(
                "Initialization".into(),
                format!("Loading LUA scripts, received database error: {}", err),
            ))
        }
    }
}
