use std::time::SystemTime;

use didcomm::Message;
use serde::Deserialize;
use serde_json::Value;
use tracing::info;
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

    let from: String = if let Some(from) = &msg.from {
        from.into()
    } else {
        return Err(MediatorError::RequestDataError(
            "-1".into(),
            "Message missing 'from' field".into(),
        ));
    };

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

    let respond: bool = if let Some(body) = msg.body.as_str() {
        if let Ok(respond) = serde_json::from_str::<Ping>(body) {
            respond.response_requested
        } else {
            // Defaults to true
            true
        }
    } else {
        // Defaults to true
        true
    };

    info!(
        "{}: Ping message received from: ({}) Respond?({})",
        session.tx_id, &from, respond
    );

    if respond {
        // Build the message (we swap from and to)
        Ok(Some(
            Message::build(
                Uuid::new_v4().into(),
                "https://didcomm.org/trust-ping/2.0/ping".to_owned(),
                Value::Null,
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
