use std::time::SystemTime;

use atn_atm_didcomm::Message;
use serde::Deserialize;
use serde_json::json;
use tracing::{debug, info, span};
use uuid::Uuid;

use crate::{
    common::errors::{MediatorError, Session},
    messages::ProcessMessageResponse,
};

const FORWARD_REQUEST_TTL_IN_SEC: u64 = 3_600;

// Reads the body of an incoming trust-ping and whether to generate a return ping message
#[derive(Deserialize)]
struct ForwardRequest {
    next: Option<String>, // Defaults to true
}

impl Default for ForwardRequest {
    fn default() -> Self {
        Self {
            next: None,
        }
    }
}

/// Process a trust-ping message and generates a response if needed
pub(crate) fn process(
    msg: &Message,
    session: &Session,
) -> Result<ProcessMessageResponse, MediatorError> {
    let _span = span!(
        tracing::Level::DEBUG,
        "routing",
        session_id = session.session_id.as_str()
    )
    .entered();
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

    let to = if let Some(to) = &msg.to {
        if let Some(first) = to.first() {
            first.to_owned()
        } else {
            return Err(MediatorError::RequestDataError(
                session.session_id.clone(),
                "Message missing valid 'to' field, expect at least one address in array.".into(),
            ));
        }
    } else {
        return Err(MediatorError::RequestDataError(
            session.session_id.clone(),
            "Message missing 'to' field".into(),
        ));
    };

    let next: String = if let Ok(body) = serde_json::from_value::<ForwardRequest>(msg.body.to_owned()) {
        match body.next {
          Some(next_str) => next_str,
          None => return Err(MediatorError::RequestDataError(
            session.session_id.clone(),
            "Message missing valid 'next' field".into(),
        )),
        }
    } else {
        return Err(MediatorError::RequestDataError(
            session.session_id.clone(),
            "Message is not a valid ForwardRequest".into(),
        ))
    };
    debug!("Forward to: {}", next);

    info!(
        "Forward request received from: ({}) Next is ({})",
        msg.from.clone().unwrap_or_else(|| "ANONYMOUS".to_string()),
        next
    );

    let attachments = if let Some(attachments) = &msg.attachments {
        attachments.to_owned()
    } else {
        return Err(MediatorError::RequestDataError(
            session.session_id.clone(),
            "Nothing to forward, attachments are not defined!".into(),
        ));
    };

    // let messages_to_forward: Vec<Message> = vec![];
    // for attachment in attachments {
    //     attachment.data
        
    
    //     debug!("response_msg: {:?}", response_msg);
    // }
    // Build the message (we swap from and to)

    let response_msg = Message::build(
        Uuid::new_v4().into(),
        msg.type_.to_owned(),
        json!({}),
    )
    .thid(msg.id.clone()) // should we reuse msg.thid?
    .to(next) // to next buddy in chain
    .from(to) // from mediator
    .created_time(now)
    .expires_time(now + FORWARD_REQUEST_TTL_IN_SEC)
    .attachments(attachments) // the value should be taken from config, how much we are ok to store the messages in the db
    .finalize();
 

    Ok(ProcessMessageResponse {
        store_message: true,
        force_live_delivery: false,
        message: Some(response_msg),
    })
}
