use crate::SharedData;
use axum::{extract::State, response::IntoResponse, routing::post, Json, Router};

pub mod message_inbound;
pub mod message_outbound;

pub fn application_routes(shared_data: &SharedData) -> Router {
    let app = Router::new().route("/inbound", post(message_inbound::message_inbound_handler));

    Router::new()
        .nest("/asm/v1/", app)
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
