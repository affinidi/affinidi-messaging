use crate::SharedData;
use axum::{
    extract::State,
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};

pub mod authenticate;
pub mod message_delete;
pub mod message_inbound;
pub mod message_list;
pub mod message_outbound;

pub fn application_routes(shared_data: &SharedData) -> Router {
    let app = Router::new()
        .route("/inbound", post(message_inbound::message_inbound_handler))
        .route(
            "/outbound",
            post(message_outbound::message_outbound_handler),
        )
        .route(
            "/list/:did_hash/:folder",
            get(message_list::message_list_handler),
        )
        .route("/delete", delete(message_delete::message_delete_handler))
        .route(
            "/authenticate/challenge",
            post(authenticate::authentication_challenge),
        )
        .route("/authenticate", post(authenticate::authentication_response));

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
        "STATUS": "success".to_string(),
        "message": message,
    });
    Json(response_json)
}
