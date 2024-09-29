use affinidi_messaging_didcomm::Message;
use serde::Deserialize;
use ssi::dids::{document::service::Endpoint, Document};
use std::time::SystemTime;
use tracing::{debug, span, warn, Instrument};

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

        // resolve the next DID to a DIDDoc
        let next_did = state.did_resolver.resolve(&next).await.map_err(|e| {
            MediatorError::DIDError(
                session.session_id.clone(),
                next,
                format!("Couldn't resolve DID: Reason: {}", e),
            )
        })?;
        let next_did_doc = next_did.doc;

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

        // Check limits and if this forward is accepted?
        // Does next (receiver) have too many messages in queue?
        // Does the sender have too many messages in queue?
        // Too many attachments?
        // Forwarding task queue is full?
        let next_stats = state.database.get_did_stats(&next_did_hash).await?;
        if next_stats.receive_queue_count as usize + attachments.len()
            >= state.config.limits.queued_messages
        {
            warn!(
                "Next DID ({}) has too many messages waiting to be delivered",
                next_did_hash
            );
            return Err(MediatorError::ServiceLimitError(
                session.session_id.clone(),
                "Next DID has too many messages waiting to be delivered. Try again later".into(),
            ));
        }

        // forwarded messages are typically anonymous, so we don't know the sender
        // Hence we will check against the session DID for sending checks
        let from_stats = state.database.get_did_stats(&session.did_hash).await?;
        if from_stats.send_queue_count as usize + attachments.len()
            >= state.config.limits.queued_messages
        {
            warn!(
                "Sender DID ({}) has too many messages waiting to be delivered",
                session.did_hash
            );
            return Err(MediatorError::ServiceLimitError(
                session.session_id.clone(),
                "Sender DID has too many messages waiting to be delivered. Try again later".into(),
            ));
        }

        if attachments.len() > state.config.limits.attachments_max_count {
            warn!(
                "Too many attachments in message, limit is {}",
                state.config.limits.attachments_max_count
            );
            return Err(MediatorError::ServiceLimitError(
                session.session_id.clone(),
                format!(
                    "Too many attachments in message. Max ({})",
                    state.config.limits.attachments_max_count
                ),
            ));
        }

        if state.database.get_forward_tasks_len().await? >= state.config.limits.forward_task_queue {
            warn!(
                "Forward task queue is full, limit is {}",
                state.config.limits.forward_task_queue
            );
            return Err(MediatorError::ServiceLimitError(
                session.session_id.clone(),
                format!(
                    "Forward task queue is full. Max ({})",
                    state.config.limits.forward_task_queue
                ),
            ));
        }

        // Check if a delay has been specified and if so, is it longer than we allow?
        let delay_milli = if let Some(delay_milli) = msg.extra_headers.get("delay_milli") {
            debug!("forward delay requested: ({:?})", delay_milli);
            delay_milli.as_i64().unwrap_or(0)
        } else {
            0
        };

        if delay_milli.abs() > (state.config.process_forwarding.future_time_limit as i64 * 1000) {
            warn!(
                "Forwarding delay is too long, limit is {}",
                state.config.process_forwarding.future_time_limit
            );
            return Err(MediatorError::ServiceLimitError(
                session.session_id.clone(),
                format!(
                    "Forwarding delay is too long. Max ({})",
                    state.config.process_forwarding.future_time_limit
                ),
            ));
        }

        // Forward is good, lets process the attachments and add to the queues
        // First step is to determine if the next hop is local to the mediator or remote?
        //if next_did_doc.service

        Ok(ProcessMessageResponse {
            store_message: true,
            force_live_delivery: false,
            message: None,
        })
    }
    .instrument(_span)
    .await
}

/// Determines if the next hop is local to the mediator or remote
/// The next field of a routing message is a DID
/// https://identity.foundation/didcomm-messaging/spec/#routing-protocol-20
/// - next: DID (may include key ID) of the next hop
/// - next_doc: Resolved DID Document of the next hop
///
/*
{
    "id": "did:example:123456789abcdefghi#didcomm-1",
    "type": "DIDCommMessaging",
    "serviceEndpoint": [{
        "uri": "https://example.com/path",
        "accept": [
            "didcomm/v2",
            "didcomm/aip2;env=rfc587"
        ],
        "routingKeys": ["did:example:somemediator#somekey"]
    }]
}
*/
fn service_local(
    session: &Session,
    state: &SharedData,
    next: &str,
    next_doc: &Document,
) -> Result<bool, MediatorError> {
    let mut _error = None;

    // If the next hop is the mediator itself, then this is a recursive forward
    if next == state.config.mediator_did {
        warn!("next hop is the mediator itself, but this should have been unpacked. not accepting this message");
        return Err(MediatorError::ForwardMessageError(
            session.session_id.clone(),
            "next hop is the mediator, recursive forward found".into(),
        ));
    }

    let local = next_doc
        .service
        .iter()
        .filter(|s| s.type_.contains(&"DIDCommMessaging".to_string()))
        .any(|s| {
            // Service Type is DIDCommMessaging
            if let Some(service_endpoint) = &s.service_endpoint {
                service_endpoint.into_iter().any(|endpoint| {
                    match endpoint {
                        Endpoint::Uri(uri) => {
                            if uri.as_str().eq(&state.config.mediator_did) {
                                warn!("next hop is the mediator itself, but this should have been unpacked. not accepting this message");
                                _error = Some(MediatorError::ForwardMessageError(session.session_id.clone(), "next hop is the mediator, recursive forward found".into()));
                                false
                            } else {
                                // Next hop is remote to the mediator
                                false
                            }
                        }
                        Endpoint::Map(map) => {true}
                    }
                })
            } else {
                false
            }
        });

    if let Some(e) = _error {
        Err(e)
    } else {
        Ok(local)
    }
}
