use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    common::errors::{AppError, MediatorError},
    database::session::Session,
    messages::inbound::handle_inbound,
    tasks::websocket_streaming::{StreamingUpdate, StreamingUpdateState, WebSocketCommands},
    SharedData,
};
use affinidi_messaging_didcomm::{Message as DidcommMessage, PackEncryptedOptions};
use affinidi_messaging_sdk::messages::problem_report::{
    ProblemReport, ProblemReportScope, ProblemReportSorter,
};
use axum::{
    extract::{
        ws::{Message, WebSocket},
        State, WebSocketUpgrade,
    },
    response::IntoResponse,
};
use serde_json::json;
use tokio::{
    select,
    sync::mpsc::{self, Receiver, Sender},
};
use tracing::{debug, info, span, warn, Instrument};
use uuid::Uuid;

/// Handles the switching of the protocol to a websocket connection
/// ACL_MODE: Rquires LOCAL access
pub async fn websocket_handler(
    session: Session,
    ws: WebSocketUpgrade,
    State(state): State<SharedData>,
) -> impl IntoResponse {
    let _span = span!(
        tracing::Level::INFO,
        "websocket_handler",
        session = session.session_id
    );
    // ACL Check (websockets only work on local DID's)
    if session.acls.get_local() {
        async move { ws.on_upgrade(move |socket| handle_socket(socket, state, session)) }
            .instrument(_span)
            .await
    } else {
        let app_error: AppError =
            MediatorError::ACLDenied("DID does not have LOCAL access".into()).into();
        app_error.into_response()
    }
}

/// WebSocket state machine. This is spawned per connection.
async fn handle_socket(mut socket: WebSocket, state: SharedData, session: Session) {
    let _span = span!(
        tracing::Level::INFO,
        "handle_socket",
        session = session.session_id
    );
    async move {
        // Register the transmission channel between websocket_streaming task and this websocket.
        let (tx, mut rx): (Sender<WebSocketCommands>, Receiver<WebSocketCommands>) = mpsc::channel(5);
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

        // Flag to prevent double deregistration
        // This can occur because in some situations the streaming-task will send a close message
        // due to duplicate channels. If we were to deregister on close in this scenario, we would
        // also deregister the new channel that is still in use.
        let mut already_deregistered_flag = false;
        loop {
            select! {
                value = socket.recv() => {
                    if let Some(msg) = value {
                        debug!("ws: Received message: {:?}", msg);
                        if let Ok(msg) = msg {
                            if let Message::Text(msg) = msg {
                                debug!("ws: Received text message: {:?}", msg);
                                if msg.len() > state.config.limits.ws_size {
                                    warn!("Error processing message, the size is too big. limit is {}, message size is {}", state.config.limits.ws_size, msg.len());
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
                            } else if let Message::Close(_) = msg {
                                debug!("Received close message, closing connection");
                                break;
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
                        match msg {
                            WebSocketCommands::Message(msg) => {
                                debug!("ws: Received message from streaming task: {:?}", msg);
                                let _ = socket.send(Message::Text(msg.into())).await;
                            },
                            WebSocketCommands::Close => {
                                if let Ok(msg) =  _generate_duplicate_connection_problem_report(&state, &session).await {
                                   let _ = socket.send(Message::Text(msg.into())).await;
                            }
                                debug!("Received close message from streaming task, closing websocket connection");
                                already_deregistered_flag = true;
                                break;
                            }
                        }
                    } else {
                        debug!("Received None from streaming task, closing connection");
                        break;
                    }
                }
            }
        }

        // Remove this websocket and associated info from the streaming task
        if !already_deregistered_flag { // Skip if close initiated by the streaming task
            if let Some(streaming) = &state.streaming_task  {
                let stop = StreamingUpdate {
                    did_hash: session.did_hash.clone(),
                    state: StreamingUpdateState::Deregister,
                };
                let _ = streaming.channel.send(stop).await;
            }
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

async fn _generate_duplicate_connection_problem_report(
    state: &SharedData,
    session: &Session,
) -> Result<String, MediatorError> {
    let problem_report = ProblemReport::new(
        ProblemReportSorter::Warning,
        ProblemReportScope::Other("websocket".to_string()),
        "duplicate-channel".to_string(),
        "A new duplicate websocket connection for this DID has caused this websocket to terminate"
            .to_string(),
        vec![],
        None,
    );

    let pr_msg = DidcommMessage::build(
        Uuid::new_v4().to_string(),
        "https://didcomm.org/report-problem/2.0/problem-report".to_string(),
        json!(problem_report),
    )
    .from(state.config.mediator_did.clone())
    .to(session.did.to_string())
    .created_time(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .finalize();

    let (packed, _) = pr_msg
        .pack_encrypted(
            &session.did,
            Some(&state.config.mediator_did),
            Some(&state.config.mediator_did),
            &state.did_resolver,
            &state.config.security.mediator_secrets,
            &PackEncryptedOptions {
                to_kids_limit: state.config.limits.to_keys_per_recipient,
                ..PackEncryptedOptions::default()
            },
        )
        .await
        .map_err(|err| {
            MediatorError::MessagePackError(
                session.session_id.clone(),
                format!("Couldn't pack DIDComm message. Reason: {}", err),
            )
        })?;

    Ok(packed)
}
