use axum::{
    extract::{
        ws::{Message, WebSocket},
        State, WebSocketUpgrade,
    },
    response::IntoResponse,
};
use tokio::{
    select,
    sync::mpsc::{self, Receiver, Sender},
};
use tracing::{debug, info, span, warn, Instrument};

use crate::{
    common::errors::Session,
    messages::inbound::handle_inbound,
    tasks::websocket_streaming::{StreamingUpdate, StreamingUpdateState},
    SharedData,
};

// Handles the switching of the protocol to a websocket connection
pub async fn websocket_handler(
    session: Session,
    ws: WebSocketUpgrade,
    State(state): State<SharedData>,
) -> impl IntoResponse {
    let _span = span!(
        tracing::Level::DEBUG,
        "websocket_handler",
        session = session.session_id
    );
    async move { ws.on_upgrade(move |socket| handle_socket(socket, state, session)) }
        .instrument(_span)
        .await
}

/// WebSocket state machine. This is spawned per connection.
async fn handle_socket(mut socket: WebSocket, state: SharedData, session: Session) {
    let _span = span!(
        tracing::Level::DEBUG,
        "handle_socket",
        session = session.session_id
    );
    async move {
        // Register the transmission channel between websocket_streaming task and this websocket.
        let (tx, mut rx): (Sender<String>, Receiver<String>) = mpsc::channel(5);
        if let Some(streaming) = &state.streaming_task {

            let start = StreamingUpdate {
                did_hash: session.did_hash.clone(),
                state: StreamingUpdateState::Register(tx),
            };
            match streaming.channel.send(start).await {
                Ok(_) => {
                    debug!("Sent start message to streaming task");
                }
                Err(e) => {
                    warn!("Error sending start message to streaming task: {:?}", e);
                    return;
                }
            }
        }

        let _ = state.database.global_stats_increment_websocket_open().await;
        info!("Websocket connection established");

        loop {
            select! {
                value = socket.recv() => {
                    if let Some(msg) = value {
                        info!("ws: Received message: {:?}", msg);
                        if let Ok(msg) = msg {
                            if let Message::Text(msg) = msg {
                                debug!("ws: Received text message: {:?}", msg);
                                if msg.len() > state.config.ws_size_limit as usize {
                                    warn!("Error processing message, the size is too big. limit is {}, message size is {}", state.config.ws_size_limit, msg.len());
                                    break;
                                }

                                // Process the message, which also takes care of any storing and live-streaming of the message
                                match handle_inbound(&state, &session, &msg).await {
                                    Ok(response) => {
                                        debug!("Successful handling of message - finished processing");
                                        response
                                    }
                                    Err(e) => {
                                        warn!("Error processing message: {:?}", e);
                                        continue;
                                    }
                                };
                            } else {
                                warn!("Received non-text message, ignoring");
                                continue;
                            }
                        }
                    } else {
                        debug!("Received None, closing connection");
                        break;
                    }
                }
                value = rx.recv() => {
                    if let Some(msg) = value {
                        debug!("ws: Received message from streaming task: {:?}", msg);
                        let _ = socket.send(Message::Text(msg)).await;
                    } else {
                        debug!("Received None from streaming task, closing connection");
                        break;
                    }
                }
            }
        }

        // Remove this websocket and associated info from the streaming task
        if let Some(streaming) = &state.streaming_task {
            let stop = StreamingUpdate {
                did_hash: session.did_hash.clone(),
                state: StreamingUpdateState::Deregister,
            };
            let _ = streaming.channel.send(stop).await;
        }

        // We're done, close the connection
        let _ = state
            .database
            .global_stats_increment_websocket_close()
            .await;

        info!("Websocket connection closed");
    }
    .instrument(_span)
    .await
}
