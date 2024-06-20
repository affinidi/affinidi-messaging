use std::io::ErrorKind;

use axum::{
    extract::{
        ws::{Message, WebSocket},
        State, WebSocketUpgrade,
    },
    response::IntoResponse,
};
use tracing::{debug, info, span, warn, Instrument};

use crate::{common::errors::Session, messages::inbound::handle_inbound, SharedData};

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
        let _ = state.database.global_stats_increment_websocket_open().await;

        info!("Websocket connection established");
        loop {
            let msg = if let Some(msg) = socket.recv().await {
                match msg {
                    Ok(msg) => {
                        info!("Received message: {:?}", msg);
                        if let Message::Text(msg) = msg {
                            debug!("Received text message: {:?}", msg);
                            msg
                        } else {
                            warn!("Received non-text message, ignoring");
                            continue;
                        }
                    }
                    Err(e) => {
                        let inner = e.into_inner();
                        if let Some(err) = inner.source() {
                            if let Some(io_error) = err.downcast_ref::<std::io::Error>() {
                                if io_error.kind() == ErrorKind::UnexpectedEof {
                                    // WebSocket closed - can safely ignore and exit
                                    break;
                                }
                            }
                        }
                        warn!("Error receiving message: {}", inner.to_string());
                        break;
                    }
                }
            } else {
                debug!("Received None, closing connection");
                break;
            };

            // Process the message
            let messages = match handle_inbound(&state, &session, &msg).await {
                Ok(messages) => messages,
                Err(e) => {
                    warn!("Error processing message: {:?}", e);
                    break;
                }
            };

            debug!("Sending response: {} messages", messages.messages.len());

            // Send responses
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
