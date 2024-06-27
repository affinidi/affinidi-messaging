use std::time::Duration;

use redis::aio::PubSub;
use tokio::time::sleep;
use tokio_stream::StreamExt;
use tracing::{debug, error, info, span, Instrument, Level};

use crate::{common::errors::MediatorError, database::DatabaseHandler};

// Useful links on redis pub/sub in Rust:
// https://github.com/redis-rs/redis-rs/issues/509
// Harrison

async fn _start_pubsub(database: DatabaseHandler, uuid: &str) -> Result<PubSub, MediatorError> {
    let _span = span!(Level::INFO, "_start_pubsub");

    async move {
        let mut pubsub = database.get_pubsub_connection().await?;

        let channel = format!("CHANNEL:{}", uuid);
        pubsub.subscribe(channel.clone()).await.map_err(|err| {
            error!("Error subscribing to channel: {}", err);
            MediatorError::DatabaseError(
                "NA".into(),
                format!("Error subscribing to channel: {}", err),
            )
        })?;

        info!("Subscribed to channel: {}", channel);
        Ok(pubsub)
    }
    .instrument(_span)
    .await
}

/// Streams messages to subscribed clients over websocket.
/// Is spawned as a task from main().
pub async fn ws_streaming(database: DatabaseHandler, uuid: String) -> Result<(), MediatorError> {
    let _span = span!(Level::INFO, "ws_streaming", uuid = uuid);

    async move {
        debug!("Starting ws_streaming thread...");

        // Clean up any existing sessions left over from previous runs
        database.clean_start_streaming(&uuid).await?;

        // Start streaming messages to clients
        let mut pubsub = _start_pubsub(database.clone(), &uuid).await?;
        loop {
            let mut stream = pubsub.on_message();

            if let Some(msg) = stream.next().await {
                if let Ok(payload) = msg.get_payload::<String>() {
                    info!("Received message: {}", payload);
                } else {
                    error!("Error getting payload from message");
                    continue;
                };
            } else {
                // Redis connection dropped, need to retry
                error!("Redis connection dropped, retrying...");
                drop(stream);

                pubsub = loop {
                    sleep(Duration::from_secs(1)).await;
                    match _start_pubsub(database.clone(), &uuid).await {
                        Ok(pubsub) => break pubsub,
                        Err(err) => {
                            error!("Error starting pubsub: {}", err);
                            continue;
                        }
                    }
                }
            }
        }
    }
    .instrument(_span)
    .await
}
