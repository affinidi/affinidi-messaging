use std::time::SystemTime;

use affinidi_messaging_didcomm::Message;
use serde::Deserialize;
use tracing::{debug, info, span, Instrument};

use crate::{
    common::errors::{MediatorError, Session},
    messages::ProcessMessageResponse,
    SharedData,
};

// Reads the body of an incoming forward message
#[derive(Default, Deserialize)]
struct ForwardRequest {
    next: Option<String>, // Defaults to true
}

/// Process a forward message, run checks and then if accepted place into FORWARD_TASKS stream
pub(crate) async fn process(
    msg: &Message,
    state: &SharedData,
    session: &Session,
) -> Result<ProcessMessageResponse, MediatorError> {
    let _span = span!(
        tracing::Level::DEBUG,
        "routing",
        session_id = session.session_id.as_str()
    );
    async move {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if let Some(expires) = msg.expires_time {
            if expires <= now {
                debug!(
                    "Message expired at ({}) now({}) seconds_ago({})",
                    expires,
                    now,
                    now - expires
                );
                return Err(MediatorError::MessageExpired(
                    session.session_id.clone(),
                    expires.to_string(),
                    now.to_string(),
                ));
            }
        }

        let next: String =
            if let Ok(body) = serde_json::from_value::<ForwardRequest>(msg.body.to_owned()) {
                match body.next {
                    Some(next_str) => next_str,
                    None => {
                        return Err(MediatorError::RequestDataError(
                            session.session_id.clone(),
                            "Message missing valid 'next' field".into(),
                        ))
                    }
                }
            } else {
                return Err(MediatorError::RequestDataError(
                    session.session_id.clone(),
                    "Message is not a valid ForwardRequest, next is required in body".into(),
                ));
            };
        let next_did_hash = sha256::digest(next.as_bytes());

        let attachments = if let Some(attachments) = &msg.attachments {
            attachments.to_owned()
        } else {
            return Err(MediatorError::RequestDataError(
                session.session_id.clone(),
                "Nothing to forward, attachments are not defined!".into(),
            ));
        };
        let attachments_bytes = attachments
            .iter()
            .map(|a| a.byte_count.unwrap_or(0))
            .sum::<u64>();
        debug!(
            "Attachments: count({}) bytes({})",
            attachments.len(),
            attachments_bytes
        );

        // Check if next hop has free capacity
        let next_stats = state.database.get_did_stats(&next_did_hash).await?;
        //if next_stats.send_queue_bytes + attachments_bytes > state.config.max

        Ok(ProcessMessageResponse {
            store_message: true,
            force_live_delivery: false,
            message: None,
        })
    }
    .instrument(_span)
    .await
}
