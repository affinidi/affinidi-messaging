use std::{collections::HashMap, time::Duration};

use redis::aio::PubSub;
use tokio::{select, sync::mpsc, task::JoinHandle, time::sleep};
use tokio_stream::StreamExt;
use tracing::{debug, error, info, span, Instrument, Level};

use crate::{common::errors::MediatorError, database::DatabaseHandler};

// Useful links on redis pub/sub in Rust:
// https://github.com/redis-rs/redis-rs/issues/509

/// Used when updating the streaming state.
/// Start: Start streaming messages to clients.
/// Stop: Stop streaming messages to clients.
pub enum StreamingUpdateState {
    Start(mpsc::Sender<String>),
    Stop,
}

/// Used to update the streaming state.
/// did_hash: The DID hash to update the state for.
/// state: The state to update to.
pub struct StreamingUpdate {
    pub did_hash: String,
    pub state: StreamingUpdateState,
}

#[derive(Clone)]
pub struct StreamingTask {
    pub channel: mpsc::Sender<StreamingUpdate>,
}

impl StreamingTask {
    /// Creates the streaming task handler
    pub async fn new(
        database: DatabaseHandler,
        mediator_uuid: &str,
    ) -> Result<(Self, JoinHandle<()>), MediatorError> {
        let _span = span!(Level::INFO, "StreamingTask::new");

        async move {
            // Create the inter-task channel - allows up to 10 queued messages
            let (tx, mut rx) = mpsc::channel(10);
            let task = StreamingTask {
                channel: tx.clone(),
            };

            // Start the streaming task
            // With it's own clone of required data
            let handle = {
                let _mediator_uuid = mediator_uuid.to_string();
                let _task = task.clone();
                tokio::spawn(async move {
                    _task
                        .ws_streaming(database, &mut rx, _mediator_uuid)
                        .await
                        .expect("Error starting websocket_streaming thread");
                })
            };

            Ok((task, handle))
        }
        .instrument(_span)
        .await
    }

    /// Starts a pubsub connection to Redis and subscribes to a channel.
    /// Useful way to restart a terminated connection from within a loop.
    async fn _start_pubsub(
        &self,
        database: DatabaseHandler,
        uuid: &str,
    ) -> Result<PubSub, MediatorError> {
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
    /// Is spawned as a task
    async fn ws_streaming(
        &self,
        database: DatabaseHandler,
        channel: &mut mpsc::Receiver<StreamingUpdate>,
        uuid: String,
    ) -> Result<(), MediatorError> {
        let _span = span!(Level::INFO, "ws_streaming", uuid = uuid);

        async move {
            debug!("Starting ws_streaming thread...");

            // Clean up any existing sessions left over from previous runs
            database.clean_start_streaming(&uuid).await?;

            let mut clients: HashMap<String, mpsc::Sender<String>> = HashMap::new();

            // Start streaming messages to clients
            let mut pubsub = self._start_pubsub(database.clone(), &uuid).await?;
            loop {
                let mut stream = pubsub.on_message();

                // Listen for an update on either the redis pubsub stream, or the command channel
                // stream: redis pubsub of incoming messages destined for a client
                // channel: command channel to start/stop streaming for a client
                select! {
                    value = stream.next() => {
                        if let Some(msg) = value {
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
                                match self._start_pubsub(database.clone(), &uuid).await {
                                    Ok(pubsub) => break pubsub,
                                    Err(err) => {
                                        error!("Error starting pubsub: {}", err);
                                        continue;
                                    }
                                }
                            }
                        }
                    }
                    value = channel.recv() => {
                        if let Some(value) = value {
                            match value.state {
                                StreamingUpdateState::Start(client_tx) => {
                                    info!("Starting streaming for DID: {}", value.did_hash);
                                    clients.insert(value.did_hash.clone(), client_tx);
                                }
                                StreamingUpdateState::Stop => {
                                    info!("Stopping streaming for DID: {}", value.did_hash);
                                    clients.remove(value.did_hash.as_str());
                                }
                            }
                        }
                    }
                }
            }
        }
        .instrument(_span)
        .await
    }
}
