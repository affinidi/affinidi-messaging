use affinidi_messaging_mediator_common::errors::{AppError, MediatorError, SuccessResponse};
use affinidi_messaging_sdk::messages::{GetMessagesRequest, GetMessagesResponse};
use axum::{extract::State, Json};
use http::StatusCode;
use tracing::{debug, span, Instrument, Level};

use crate::{database::session::Session, SharedData};

/// Delivers messages to the client for given message_ids
/// outbound refers to outbound from the mediator perspective
/// ACL_MODE: Rquires LOCAL access
pub async fn message_outbound_handler(
    session: Session,
    State(state): State<SharedData>,
    Json(body): Json<GetMessagesRequest>,
) -> Result<(StatusCode, Json<SuccessResponse<GetMessagesResponse>>), AppError> {
    let _span = span!(
        Level::DEBUG,
        "message_outbound_handler",
        session = session.session_id,
        delete = body.delete,
    );
    async move {
        // ACL Check
        if !session.acls.get_local() {
            return Err(MediatorError::ACLDenied("DID does not have LOCAL access".into()).into());
        }

        debug!(
            "Client has asked to get ({}) messages",
            body.message_ids.len()
        );

        let mut messages = GetMessagesResponse::default();

        for msg_id in &body.message_ids {
            debug!("getting message with id: {}", msg_id);
            match state.database.get_message(&session.did_hash, msg_id).await {
                Ok(msg) => {
                    debug!("Got message: {:?}", msg);
                    messages.success.push(msg);

                    if body.delete {
                        debug!("Deleting message: {}", msg_id);
                        match state
                            .database
                            .delete_message(&session.session_id, &session.did_hash, msg_id)
                            .await
                        {
                            Ok(_) => {
                                debug!("Deleted message: {}", msg_id);
                            }
                            Err(err) => {
                                debug!("Error deleting message: {:?}", err);
                                messages
                                    .delete_errors
                                    .push((msg_id.clone(), err.to_string()));
                            }
                        }
                    }
                }
                Err(err) => {
                    debug!("Error getting message: {:?}", err);
                    messages.get_errors.push((msg_id.clone(), err.to_string()));
                }
            }
        }

        Ok((
            StatusCode::OK,
            Json(SuccessResponse {
                sessionId: session.session_id,
                httpCode: StatusCode::OK.as_u16(),
                errorCode: 0,
                errorCodeStr: "NA".to_string(),
                message: "Success".to_string(),
                data: Some(messages),
            }),
        ))
    }
    .instrument(_span)
    .await
}
