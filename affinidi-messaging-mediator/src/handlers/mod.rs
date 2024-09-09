use crate::SharedData;
use axum::{
    extract::State,
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};

pub mod authenticate;
pub mod inbox_fetch;
pub mod message_delete;
pub mod message_inbound;
pub mod message_list;
pub mod message_outbound;
pub mod websocket;
pub mod well_known_did_fetch;

pub fn application_routes(shared_data: &SharedData) -> Router {
    let app = Router::new()
        // Inbound message handling from ATM clients
        .route("/inbound", post(message_inbound::message_inbound_handler))
        // Outbound message handling to ATM clients
        .route(
            "/outbound",
            post(message_outbound::message_outbound_handler),
        )
        .route("/fetch", post(inbox_fetch::inbox_fetch_handler))
        // Listing of messages for a DID
        .route(
            "/list/:did_hash/:folder",
            get(message_list::message_list_handler),
        )
        // Delete/remove messages stored in ATM
        .route("/delete", delete(message_delete::message_delete_handler))
        // Authentication step 1/2 - Client requests challenge from server
        .route(
            "/authenticate/challenge",
            post(authenticate::authentication_challenge),
        )
        // Authentication step 2/2 - Client sends encrypted challenge to server
        .route("/authenticate", post(authenticate::authentication_response))
        // Websocket endpoint for ATM clients
        .route("/ws", get(websocket::websocket_handler))
        .route(
            "/.well-known/did",
            get(well_known_did_fetch::well_known_did_fetch_handler),
        );

    Router::new()
        .nest("/atm/v1/", app)
        .with_state(shared_data.to_owned())
}

pub async fn health_checker_handler(State(state): State<SharedData>) -> impl IntoResponse {
    let message: String = format!(
        "Affinidi Secure Messaging Mediator Service, Version: {}, Started: UTC {}",
        env!("CARGO_PKG_VERSION"),
        state.service_start_timestamp.format("%Y-%m-%d %H:%M:%S"),
    );

    let response_json = serde_json::json!({
        "status": "success".to_string(),
        "message": message,
    });
    Json(response_json)
}
