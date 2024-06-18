use axum::{
    extract::{ws::WebSocket, State, WebSocketUpgrade},
    response::IntoResponse,
    Json,
};
use tracing::{info, span, Instrument};

use crate::{common::errors::Session, SharedData};

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

async fn handle_socket(mut socket: WebSocket, state: SharedData, session: Session) {
    let _span = span!(tracing::Level::DEBUG, "handle_socket");
    async move {
        let _guard = Guard;
        info!("Websocket connection established");
    }
    .instrument(_span)
    .await
}

struct Guard;

impl Drop for Guard {
    fn drop(&mut self) {
        info!("Websocket connection closed");
    }
}
