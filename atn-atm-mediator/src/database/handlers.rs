use std::{
    thread::sleep,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use atn_atm_sdk::messages::list::{Folder, MessageList, MessageListElement};
use deadpool_redis::Connection;
use itertools::Itertools;
use redis::{from_redis_value, Value};
use serde::Serialize;
use sha256::digest;
use tracing::{debug, event, span, Instrument, Level};

use crate::common::{config::Config, errors::MediatorError};

use super::{DatabaseHandler, MetadataStats};

/// Used to store the timestamp of a message so we can expire them
/// message_sha: ID of the message in the MESSAGE_STORE hash
/// timestamp: Unix timestamp of when the message was created (in seconds)
#[derive(Serialize)]
struct ExpiryRecord {
    pub message_hash: String,
    pub timestamp: u64,
}

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

    /// Stores a message in the database
    /// Step 1: Create a transaction
    /// Step 2: Store the message in the MESSAGE_STORE hash
    /// Step 3: Increment the MESSAGE_STORE bytes_stored field
    /// Step 4: Store the sender in the SEND_Q_<DID_HASH> LIST (this may not be required if anonymous sender)
    /// Step 5: Update DID_<hash> for sender stats
    /// Step 6: Create a pointer in the EXPIRY_LIST List
    /// Step 7: Update DID_<hash> for recipient stats
    /// Step 8: Update DID_LIST (Hash) for mapping of DID/hash values
    /// Step 9: Create a pointer in the RECEIVE_Q_<DID_HASH> Stream
    /// Step 10: Commit the transaction
    pub async fn store_message(
        &self,
        session_id: &str,
        message: &str,
        to_did: &str,
        from_did: Option<&str>,
    ) -> Result<(), MediatorError> {
        let _span = span!(Level::DEBUG, "store_message", session_id = session_id);
        async move {
            let to_did_hash = digest(to_did);

            // step 1
            let mut tx = deadpool_redis::redis::pipe();
            tx.atomic();

            // step 2: store the message
            let message_hash = digest(message.as_bytes());
            tx.cmd("HSET")
                .arg("MESSAGE_STORE")
                .arg(&message_hash)
                .arg(message);

            // step 3: increment the bytes stored
            tx.cmd("HINCRBY")
                .arg("MESSAGE_STORE")
                .arg("bytes_stored")
                .arg(message.len());

            // step 4: store the sender
            // step 5: update the sender stats
            // step 8: update the DID_LIST for sender
            if let Some(from_did) = from_did {
                let from_did_hash = digest(from_did.as_bytes());

                tx.cmd("XADD")
                    .arg(format!("SEND_Q_{}", from_did_hash))
                    .arg("*")
                    .arg("msg_id")
                    .arg(&message_hash)
                    .arg("bytes")
                    .arg(message.len())
                    .arg("address")
                    .arg(to_did)
                    .cmd("HINCRBY")
                    .arg(format!("DID_{}", from_did_hash))
                    .arg(
                        "send_bytes_queued
                ",
                    )
                    .arg(message.len())
                    .cmd("HINCRBY")
                    .arg(format!("DID_{}", from_did_hash))
                    .arg("send_queued")
                    .arg("1")
                    .cmd("HSET")
                    .arg("DID_LIST")
                    .arg(&from_did_hash)
                    .arg(from_did)
                    .arg(from_did)
                    .arg(&from_did_hash);
                debug!(
                    "sender: did({}) did_hash({}) bytes({})",
                    from_did,
                    from_did_hash,
                    message.len()
                );
            }

            // step 6: create a pointer in the EXPIRY_LIST
            let er = ExpiryRecord {
                message_hash: message_hash.clone(),
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            };
            tx.cmd("RPUSH")
                .arg("EXPIRY_LIST")
                .arg(serde_json::to_string(&er).unwrap());

            // step 7: update the recipient stats
            // step 8: update the DID_LIST
            // step 9: create a pointer in the RECEIVE_Q
            tx.cmd("HINCRBY")
                .arg(format!("DID_{}", to_did_hash))
                .arg("receive_bytes_queued")
                .arg(message.len())
                .cmd("HINCRBY")
                .arg(format!("DID_{}", to_did_hash))
                .arg("receive_queued")
                .arg("1")
                .cmd("HSET")
                .arg("DID_LIST")
                .arg(&to_did_hash)
                .arg(to_did)
                .arg(to_did)
                .arg(&to_did_hash)
                // Add to stream
                .cmd("XADD")
                .arg(format!("RECEIVE_Q_{}", to_did_hash))
                .arg("*")
                .arg("msg_id")
                .arg(&message_hash)
                .arg("bytes")
                .arg(message.len())
                .arg("address")
                .arg(from_did.unwrap_or("anonymous"));

            debug!("receiver: did({}) did_hash({})", to_did, to_did_hash,);

            let mut con = self.get_connection().await?;

            // Write the transaction
            tx.query_async(&mut con).await.map_err(|err| {
                event!(Level::ERROR, "Couldn't store message in database: {}", err);
                MediatorError::DatabaseError(
                    session_id.into(),
                    format!("Couldn't store message in database: {}", err),
                )
            })?;

            debug!("Message hash({}) stored in database", er.message_hash);

            Ok(())
        }
        .instrument(_span)
        .await
    }

    /// Retrieves metadata statistics that are global to the mediator database
    /// This means it may include more than this mediator's messages
    pub async fn get_db_metadata(&self) -> Result<MetadataStats, MediatorError> {
        let mut conn = self.get_connection().await?;

        let mut stats = MetadataStats::new();

        let (bytes_stored, message_count, did_count): (Option<u64>, Option<u64>, Option<u64>) =
            deadpool_redis::redis::pipe()
                .cmd("HGET")
                .arg("METADATA")
                .arg("bytes_stored")
                .cmd("HLEN")
                .arg("MESSAGE_STORE")
                .cmd("HLEN")
                .arg("DID_LIST")
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

        stats.bytes_stored = bytes_stored.unwrap_or(0);
        stats.message_count = message_count.unwrap_or(0);
        if stats.message_count > 1 {
            stats.message_count -= 1; // Remove the bytes_stored counter itself
        }
        stats.did_count = did_count.unwrap_or(0);
        if stats.did_count > 0 {
            stats.did_count /= 2; // Halve the count as we store the DID and the hash
        }
        event!(Level::INFO, "Shared METADATA: {}", stats);

        Ok(stats)
    }

    pub async fn list_messages(
        &self,
        did: &str,
        folder: Folder,
    ) -> Result<MessageList, MediatorError> {
        let mut conn = self.get_connection().await?;

        let did_hash = digest(did.as_bytes());
        debug!("DID_HASH: {}", did_hash);
        let key = match folder {
            Folder::Inbox => format!("RECEIVE_Q_{}", did_hash),
            Folder::Outbox => format!("SEND_Q_{}", did_hash),
        };

        let db_response: Value = deadpool_redis::redis::cmd("XRANGE")
            .arg(&key)
            .arg("-")
            .arg("+")
            .query_async(&mut conn)
            .await
            .map_err(|err| {
                event!(
                    Level::ERROR,
                    "Couldn't get message_list({}) from database for DID {}: {}",
                    key,
                    did,
                    err
                );
                MediatorError::DatabaseError(
                    did.into(),
                    format!(
                        "Couldn't get message_list({}) from database for DID {}: {}",
                        key, did, err
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

        let items: Vec<Value> = from_redis_value(&db_response).map_err(|e| _error(e, did, &key))?;

        for item in items {
            // item = Bulk(string(id), Bulk(fields...))
            let item: Vec<Value> = from_redis_value(&item).unwrap();
            let mut msg_element = MessageListElement {
                list_id: from_redis_value(&item[0]).map_err(|e| _error(e, did, &key))?,
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
                from_redis_value(&item[1]).map_err(|e| _error(e, did, &key))?;

            for (k, v) in fields.iter().tuples() {
                match k.as_str() {
                    "msg_id" => msg_element.msg_id.clone_from(v),
                    "bytes" => msg_element.msg_size = v.parse().unwrap_or(0),
                    "address" => msg_element.msg_address.clone_from(v),
                    _ => {}
                }
            }
            messages.push(msg_element);
        }

        Ok(messages)
    }
}
