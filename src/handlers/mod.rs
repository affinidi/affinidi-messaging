use axum::{extract::State, response::IntoResponse, Json};

use crate::SharedData;

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
