use affinidi_messaging_didcomm::{Attachment, Message};
use affinidi_messaging_sdk::{
    messages::fetch::FetchOptions,
    protocols::message_pickup::{
        MessagePickupDeliveryRequest, MessagePickupLiveDelivery, MessagePickupStatusReply,
        MessagePickupStatusRequest,
    },
};
use base64::prelude::*;
use itertools::Itertools;
use redis::{from_redis_value, Value};
use serde_json::json;
use sha256::digest;
use std::time::SystemTime;
use tracing::{debug, error, event, info, span, warn, Instrument, Level};
use uuid::Uuid;

use crate::{
    common::errors::{MediatorError, Session},
    messages::ProcessMessageResponse,
    tasks::websocket_streaming::{StreamingUpdate, StreamingUpdateState},
    SharedData,
};

/// Process a Status Request message and generates a response
pub(crate) async fn status_request(
    msg: &Message,
    state: &SharedData,
    session: &Session,
) -> Result<ProcessMessageResponse, MediatorError> {
    let _span = span!(tracing::Level::DEBUG, "status_request",);
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

    // Ensure to: exists and is valid
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
    debug!("To: {}", to);

    // Must be addressed to ATM
    if to != state.config.mediator_did {
        debug!(
            "to: ({}) doesn't match ATM DID ({})",
            to, state.config.mediator_did
        );
        return Err(MediatorError::RequestDataError(session.session_id.clone(),
         format!("message to: ({}) didn't match ATM DID ({}). Status Request messages must be addressed directly to ATM!",
          to, state.config.mediator_did)));
    }

    // Message can not be anonymous
    if msg.from.is_none() {
        return Err(MediatorError::RequestDataError(
            session.session_id.clone(),
            "Message Pickup 3.0 Status-Request can not be anonymous as it is needed from to validate permissions".into(),
        ));
    };

    // Check for extra-header `return_route`
    if let Some(header) = msg.extra_headers.get("return_route") {
        if header.as_str() != Some("all") {
            debug!(
                "return_route: extra-header exists. Expected (all) but received ({})",
                header
            );
            return Err(MediatorError::RequestDataError(
                session.session_id.clone(),
                format!(
                    "return_route: extra-header exists. Expected (all) but received ({})",
                    header
                ),
            ));
        }
    } else {
        debug!("return_route: extra-header does not exist!");
        return Err(MediatorError::RequestDataError(
            session.session_id.clone(),
            "return_route: extra-header does not exist! It should!".into(),
        ));
    }

    // Get or create the thread id for the response
    let thid = if let Some(thid) = &msg.thid {
        thid.to_owned()
    } else {
        msg.id.clone()
    };
    debug!("thid = ({})", thid);

    // Pull recipient_did from message body
    let recipient_did: String = if let Ok(body) =
        serde_json::from_value::<MessagePickupStatusRequest>(msg.body.to_owned())
    {
        if let Some(recipient_did) = body.recipient_did {
            if recipient_did != session.did {
                debug!(
                    "recipient_did: ({}) doesn't match session.did!",
                    recipient_did
                );
                return Err(MediatorError::RequestDataError(
                    session.session_id.clone(),
                    format!(
                        "recipient_did: ({}) doesn't match session.did!",
                        recipient_did
                    ),
                ));
            } else {
                digest(recipient_did)
            }
        } else {
            session.did_hash.clone()
        }
    } else {
        session.did_hash.clone()
    };
    debug!("Body: recipient_did: {}", recipient_did);

    info!(
        "MessagePickup Status-Request received from: ({}) recipient_did_hash({:?})",
        msg.from.clone().unwrap_or_else(|| "ANONYMOUS".to_string()),
        recipient_did
    );

    generate_status_reply(state, session, &recipient_did, &thid, false, None).await
}.instrument(_span).await
}

/// Creates the reply to a valid StatusRequest message
/// force_live_delivery: If true, will force the message to be live streamed even if live streaming is disabled.
///           Required due to the protocol specification to send a status update on live_streaming changes
/// override_live_delivery: If Some(bool), will override the live delivery status of the recipient
///           Because we are async handling streaming updates, we send the response before the streaming task has updated the status
async fn generate_status_reply(
    state: &SharedData,
    session: &Session,
    did_hash: &str,
    thid: &str,
    force_live_delivery: bool,
    override_live_delivery: Option<bool>,
) -> Result<ProcessMessageResponse, MediatorError> {
    let _span = span!(tracing::Level::DEBUG, "generate_status_reply",);

    async move {
        let mut conn = state.database.get_async_connection().await?;

        let response: Vec<Value> = deadpool_redis::redis::cmd("FCALL")
            .arg("get_status_reply")
            .arg(1)
            .arg(did_hash)
            .query_async(&mut conn)
            .await
            .map_err(|err| {
                event!(
                    Level::ERROR,
                    "get_status_reply({}) failed. Reason: {}",
                    did_hash,
                    err
                );
                MediatorError::DatabaseError(
                    session.session_id.clone(),
                    format!("get_status_reply({}) failed. Reason: {}", did_hash, err),
                )
            })?;

        let mut status = MessagePickupStatusReply {
            recipient_did: session.did.clone(),
            ..Default::default()
        };

        for (k, v) in response.into_iter().tuples() {
            match from_redis_value::<String>(&k).unwrap_or("".into()).as_str() {
                "newest_received" => {
                    if let Ok(v) = from_redis_value::<String>(&v) {
                        let a: Vec<&str> = v.split('-').collect();
                        if a.len() != 2 {
                            continue;
                        }
                        status.newest_received_time = if let Ok(t) = a[0].parse::<u64>() {
                            Some(t / 1000)
                        } else {
                            None
                        };
                    }
                }
                "oldest_received" => {
                    if let Ok(v) = from_redis_value::<String>(&v) {
                        let a: Vec<&str> = v.split('-').collect();
                        if a.len() != 2 {
                            continue;
                        }
                        status.oldest_received_time = if let Ok(t) = a[0].parse::<u64>() {
                            Some(t / 1000)
                        } else {
                            None
                        };
                    }
                }
                "message_count" => {
                    if let Ok(v) = from_redis_value::<u32>(&v) {
                        status.message_count = v;
                    }
                }
                "queue_count" => continue,
                "live_delivery" => {
                    if let Ok(v) = from_redis_value::<bool>(&v) {
                        status.live_delivery = v;
                    }
                }
                "total_bytes" => {
                    if let Ok(v) = from_redis_value::<u64>(&v) {
                        status.total_bytes = v;
                    }
                }
                "recipient_did" => continue,
                _ => {
                    warn!("Unknown key: ({:?}) with value: ({:?})", k, v);
                }
            }
        }

        if let Some(live_delivery) = override_live_delivery {
            status.live_delivery = live_delivery;
        }

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if let Some(t) = status.oldest_received_time {
            status.longest_waited_seconds = Some(now - t);
        }

        // Build the message
        let status_msg = Message::build(
            Uuid::new_v4().into(),
            "https://didcomm.org/messagepickup/3.0/status".to_owned(),
            json!(status),
        )
        .thid(thid.to_owned())
        .to(session.did.clone())
        .from(state.config.mediator_did.clone())
        .created_time(now)
        .expires_time(now + 300)
        .finalize();

        debug!("status message =\n{:?}", status_msg);

        Ok(ProcessMessageResponse {
            store_message: false,
            force_live_delivery,
            message: Some(status_msg),
        })
    }
    .instrument(_span)
    .await
}

/// Allows for turning on and off live delivery within ATM for a client
pub(crate) async fn toggle_live_delivery(
    msg: &Message,
    state: &SharedData,
    session: &Session,
) -> Result<ProcessMessageResponse, MediatorError> {
    let _span = span!(tracing::Level::DEBUG, "toggle_live_delivery",);
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

        // Ensure to: exists and is valid
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
        debug!("To: {}", to);

        // Must be addressed to ATM
        if to != state.config.mediator_did {
            debug!(
                "to: ({}) doesn't match ATM DID ({})",
                to, state.config.mediator_did
            );
            return Err(MediatorError::RequestDataError(session.session_id.clone(),
            format!("message to: ({}) didn't match ATM DID ({}). Live Delivery messages must be addressed directly to ATM!",
            to, state.config.mediator_did)));
        }

        // Message can not be anonymous
        if msg.from.is_none() {
            return Err(MediatorError::RequestDataError(
                session.session_id.clone(),
                "Message Pickup 3.0 Status-Request can not be anonymous as it is needed from to validate permissions".into(),
            ));
        };

        // Check for extra-header `return_route`
        if let Some(header) = msg.extra_headers.get("return_route") {
            if header.as_str() != Some("all") {
                debug!(
                    "return_route: extra-header exists. Expected (all) but received ({})",
                    header
                );
                return Err(MediatorError::RequestDataError(
                    session.session_id.clone(),
                    format!(
                        "return_route: extra-header exists. Expected (all) but received ({})",
                        header
                    ),
                ));
            }
        } else {
            debug!("return_route: extra-header does not exist!");
            return Err(MediatorError::RequestDataError(
                session.session_id.clone(),
                "return_route: extra-header does not exist! It should!".into(),
            ));
        }

        // Get or create the thread id for the response
        let thid = if let Some(thid) = &msg.thid {
            thid.to_owned()
        } else {
            msg.id.clone()
        };
        debug!("thid = ({})", thid);

        // Pull live_delivery from message body
        let live_delivery: bool = if let Ok(body) =
            serde_json::from_value::<MessagePickupLiveDelivery>(msg.body.to_owned())
        {
            body.live_delivery
        } else {
            error!("Failed to parse live_delivery from message body");
            return Err(MediatorError::RequestDataError(
                session.session_id.clone(),
                "Failed to parse live_delivery from message body".into(),
            ));
        };
        debug!("Body: live_delivery: {}", live_delivery);

        info!(
            "MessagePickup live_delivery received from: ({}) live_delivery?({})",
            msg.from.clone().unwrap_or_else(|| "ANONYMOUS".to_string()),
            live_delivery
        );

        // Take action to change live delivery status
        if live_delivery {
            // Enable Live delivery
            if let Some(stream_task) = &state.streaming_task {
                stream_task.channel.send(StreamingUpdate { did_hash: session.did_hash.clone(), state: StreamingUpdateState::Start}).await.map_err(|e| {
                    error!("Error sending start message to streaming task: {:?}", e);
                    MediatorError::InternalError(session.session_id.clone(), "Error sending start message to streaming task".into())
                })?;
            }

        } else {
            // Disable live delivery
            if let Some(stream_task) = &state.streaming_task {
                stream_task.channel.send(StreamingUpdate { did_hash: session.did_hash.clone(), state: StreamingUpdateState::Stop}).await.map_err(|e| {
                    error!("Error sending stop message to streaming task: {:?}", e);
                    MediatorError::InternalError(session.session_id.clone(), "Error sending stop message to streaming task".into())
                })?;
            }
        }

        generate_status_reply(state, session, &session.did_hash, &thid, true, Some(live_delivery)).await
    }.instrument(_span).await
}

/// Process a Delivery Request message and generates a response
pub(crate) async fn delivery_request(
    msg: &Message,
    state: &SharedData,
    session: &Session,
) -> Result<ProcessMessageResponse, MediatorError> {
    let _span = span!(tracing::Level::DEBUG, "delivery_request",);
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

    // Ensure to: exists and is valid
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
    debug!("To: {}", to);

    // Must be addressed to ATM
    if to != state.config.mediator_did {
        debug!(
            "to: ({}) doesn't match ATM DID ({})",
            to, state.config.mediator_did
        );
        return Err(MediatorError::RequestDataError(session.session_id.clone(),
         format!("message to: ({}) didn't match ATM DID ({}). Status Request messages must be addressed directly to ATM!",
          to, state.config.mediator_did)));
    }

    // Message can not be anonymous
    if msg.from.is_none() {
        return Err(MediatorError::RequestDataError(
            session.session_id.clone(),
            "Message Pickup 3.0 Status-Request can not be anonymous as it is needed from to validate permissions".into(),
        ));
    };

    // Check for extra-header `return_route`
    if let Some(header) = msg.extra_headers.get("return_route") {
        if header.as_str() != Some("all") {
            debug!(
                "return_route: extra-header exists. Expected (all) but received ({})",
                header
            );
            return Err(MediatorError::RequestDataError(
                session.session_id.clone(),
                format!(
                    "return_route: extra-header exists. Expected (all) but received ({})",
                    header
                ),
            ));
        }
    } else {
        debug!("return_route: extra-header does not exist!");
        return Err(MediatorError::RequestDataError(
            session.session_id.clone(),
            "return_route: extra-header does not exist! It should!".into(),
        ));
    }

    // Get or create the thread id for the response
    let thid = if let Some(thid) = &msg.thid {
        thid.to_owned()
    } else {
        msg.id.clone()
    };
    debug!("thid = ({})", thid);

    // Pull recipient_did and limit from message body
    let (recipient_did, limit): (String, usize) = match
        serde_json::from_value::<MessagePickupDeliveryRequest>(msg.body.to_owned())
    {
        Ok(body) =>
        (body.recipient_did, body.limit),
        Err(e) =>
        return Err(MediatorError::RequestDataError(
            session.session_id.clone(),
            format!("delivery-request body isn't valid. Reason: {}", e),
        ))
    };

    let recipient_did_hash = digest(recipient_did.clone());

    debug!("Body: recipient_did: {}, limit: {}", recipient_did_hash, limit);

    info!(
        "MessagePickup Delivery-Request received from: ({}) recipient_did({}) limit({})",
        msg.from.clone().unwrap_or_else(|| "ANONYMOUS".to_string()),
        recipient_did_hash, limit
    );

    // All the parsing is done, lets attempt to retrieve messages
    let messages = state.database.fetch_messages(&session.session_id, &recipient_did_hash, &FetchOptions {   limit, ..Default::default() }).await?;
    debug!("msgs fetched: {}", messages.success.len());

    if !messages.success.is_empty() {
        let response_msg = Message::build(Uuid::new_v4().into(), "https://didcomm.org/messagepickup/3.0/delivery".to_string(), json!({"recipient_did": recipient_did})).thid(thid.clone());

        let mut attachments: Vec<Attachment> = Vec::new();

        for element in messages.success {
            if let Some(msg) = element.msg {
                let attachment = Attachment::base64(BASE64_URL_SAFE_NO_PAD.encode(msg)).id(element.msg_id);

                attachments.push(attachment.finalize())
            }
        }

        let response_msg = response_msg.attachments(attachments).to(session.did.clone())
        .from(state.config.mediator_did.clone())
        .created_time(now)
        .expires_time(now + 300)
        .finalize();

        debug!("delivery message =\n{:?}", response_msg);

        Ok(ProcessMessageResponse {
            store_message: false,
            force_live_delivery: false,
            message: Some(response_msg),
        })
    } else {
        generate_status_reply(state, session, &recipient_did_hash, &thid, false, None).await
    }
}.instrument(_span).await
}
