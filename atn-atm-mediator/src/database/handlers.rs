use std::{thread::sleep, time::Duration};

use atn_atm_sdk::messages::list::{Folder, MessageList, MessageListElement};
use deadpool_redis::Connection;
use itertools::Itertools;
use redis::{from_redis_value, Value};
use tracing::{debug, event, span, Level};

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

        event!(Level::INFO, "Global Metadata: {}", stats);

        Ok(stats)
    }

    /// Retrieves list of messages for the specified DID and folder
    /// The folder can be either Inbox or Outbox
    /// - did_hash: The DID sha256 hash to retrieve messages for
    /// - range: stream ID range to retrieve (defaults to '-' and '+' which gets all messages)
    pub async fn list_messages(
        &self,
        did_hash: &str,
        folder: Folder,
        range: Option<(&str, &str)>,
    ) -> Result<MessageList, MediatorError> {
        let _span = span!(
            Level::DEBUG,
            "list_messages",
            did_hash = did_hash,
            folder = format!("{:?}", folder),
            range = format!("{:?}", range)
        );
        let mut conn = self.get_connection().await?;

        debug!("DID_HASH: {}", did_hash);
        let key = match folder {
            Folder::Inbox => format!("RECEIVE_Q:{}", did_hash),
            Folder::Outbox => format!("SEND_Q:{}", did_hash),
        };

        let (start, end) = if let Some((start, end)) = range {
            (start, end)
        } else {
            ("-", "+")
        };

        let db_response: Value = deadpool_redis::redis::cmd("XRANGE")
            .arg(&key)
            .arg(start)
            .arg(end)
            .query_async(&mut conn)
            .await
            .map_err(|err| {
                event!(
                    Level::ERROR,
                    "Couldn't get message_list({}) from database for DID_hash {}: {}",
                    key,
                    did_hash,
                    err
                );
                MediatorError::DatabaseError(
                    did_hash.into(),
                    format!(
                        "Couldn't get message_list({}) from database for DID_hash {}: {}",
                        key, did_hash, err
                    ),
                )
            })?;

        // The following should really be a Impl FromRedisValue for MessageList
        // But I don't want to poison the atn-atm-sdk crate with Redis and internal details
        // So I'm going to manually parse the response here
        // We could have an internal/external SDK - but that's a lot of work
        let mut messages: MessageList = Vec::new();

        // Redis response is
        // Bulk([bulk(string(id), bulk(string(field), string(field))])

        fn _error<T>(e: T, did: &str, key: &str) -> MediatorError
        where
            T: std::fmt::Display,
        {
            event!(
                Level::ERROR,
                "Couldn't parse message_list did({}) folder({}): {}",
                did,
                key,
                e
            );
            MediatorError::DatabaseError(
                "NA".into(),
                format!(
                    "Couldn't parse message_list did({}) folder({}): {}",
                    did, key, e
                ),
            )
        }

        let items: Vec<Value> =
            from_redis_value(&db_response).map_err(|e| _error(e, did_hash, &key))?;

        for item in items {
            // item = Bulk(string(id), Bulk(fields...))
            let item: Vec<Value> = from_redis_value(&item).unwrap();
            let mut msg_element = MessageListElement {
                list_id: from_redis_value(&item[0]).map_err(|e| _error(e, did_hash, &key))?,
                ..Default::default()
            };
            msg_element.msg_date = msg_element
                .list_id
                .split('-')
                .next()
                .unwrap_or("")
                .parse()
                .unwrap_or(0);

            let fields: Vec<String> =
                from_redis_value(&item[1]).map_err(|e| _error(e, did_hash, &key))?;

            for (k, v) in fields.iter().tuples() {
                match k.as_str() {
                    "MSG_ID" => msg_element.msg_id.clone_from(v),
                    "BYTES" => msg_element.msg_size = v.parse().unwrap_or(0),
                    "FROM" => msg_element.msg_address.clone_from(v),
                    "TO" => msg_element.msg_address.clone_from(v),
                    _ => {}
                }
            }
            messages.push(msg_element);
        }

        Ok(messages)
    }
}
