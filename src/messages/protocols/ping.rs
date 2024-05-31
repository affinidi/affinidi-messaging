use std::time::SystemTime;

use didcomm::Message;
use serde::Deserialize;
use serde_json::json;
use tracing::{debug, info};
use uuid::Uuid;

use crate::common::errors::{MediatorError, Session};

// Reads the body of an incoming trust-ping and whether to generate a return ping message
#[derive(Deserialize)]
struct Ping {
    response_requested: bool, // Defaults to true
}

impl Default for Ping {
    fn default() -> Self {
        Self {
            response_requested: true,
        }
    }
}

/// Process a trust-ping message and generates a response if needed
pub(crate) fn process(msg: &Message, session: &Session) -> Result<Option<Message>, MediatorError> {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let to = if let Some(to) = &msg.to {
        if let Some(first) = to.first() {
            first.to_owned()
        } else {
            return Err(MediatorError::RequestDataError(
                "-1".into(),
                "Message missing valid 'to' field, expect at least one address in array.".into(),
            ));
        }
    } else {
        return Err(MediatorError::RequestDataError(
            "-1".into(),
            "Message missing 'to' field".into(),
        ));
    };

    let respond: bool = if let Ok(body) = serde_json::from_value::<Ping>(msg.body.to_owned()) {
        body.response_requested
    } else {
        true
    };
    debug!("Respond requested: {}", respond);

    info!(
        "{}: Ping message received from: ({}) Respond?({})",
        session.session_id,
        msg.from.clone().unwrap_or_else(|| "ANONYMOUS".to_string()),
        respond
    );

    if respond {
        let from = if let Some(from) = &msg.from {
            from.to_owned()
        } else {
            return Err(MediatorError::RequestDataError(
                "-1".into(),
                "Anonymous Trust-Ping is asking for a response, this is an invalid request!".into(),
            ));
        };

        // Build the message (we swap from and to)
        Ok(Some(
            Message::build(
                Uuid::new_v4().into(),
                "https://didcomm.org/trust-ping/2.0/ping".to_owned(),
                json!({}),
            )
            .thid(msg.id.clone())
            .to(from)
            .from(to)
            .created_time(now)
            .expires_time(now + 300)
            .finalize(),
        ))
    } else {
        // No response requested
        Ok(None)
    }
}
