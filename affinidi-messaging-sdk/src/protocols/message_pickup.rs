use affinidi_messaging_didcomm::{AttachmentData, Message, PackEncryptedOptions, UnpackMetadata};
use base64::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::{select, sync::RwLock};
use tracing::{debug, span, warn, Instrument, Level};
use uuid::Uuid;

use crate::{
    errors::ATMError,
    messages::{EmptyResponse, GenericDataStruct},
    profiles::Profile,
    transports::websockets::ws_handler::WsHandlerCommands,
    ATM,
};

#[derive(Default)]
pub struct MessagePickup {}

// Reads the body of an incoming Message Pickup 3.0 Status Request Message
#[derive(Default, Deserialize)]
pub struct MessagePickupStatusRequest {
    pub recipient_did: Option<String>,
}

// Reads the body of an incoming Message Pickup 3.0 Live Delivery Message
#[derive(Default, Deserialize)]
pub struct MessagePickupLiveDelivery {
    pub live_delivery: bool,
}

// Body of a StatusRequest reply
#[derive(Default, Debug, Serialize, Deserialize)]
pub struct MessagePickupStatusReply {
    pub recipient_did: String,
    pub message_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub longest_waited_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub newest_received_time: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oldest_received_time: Option<u64>,
    pub total_bytes: u64,
    pub live_delivery: bool,
}
impl GenericDataStruct for MessagePickupStatusReply {}

// Reads the body of an incoming Message Pickup 3.0 Delivery Request Message
#[derive(Default, Deserialize, Serialize)]
pub struct MessagePickupDeliveryRequest {
    pub recipient_did: String,
    pub limit: usize,
}

// Reads the body of an incoming Message Pickup 3.0 Messages Received Message
#[derive(Default, Deserialize, Serialize)]
pub struct MessagePickupMessagesReceived {
    pub message_id_list: Vec<String>,
}
/// Handles the return from a message delivery request
/// returns
/// - StatusReply : No messages available
/// - MessageDelivery : A DIDComm message containing messages
#[derive(Serialize, Deserialize)]
enum DeliveryRequestResponse {
    StatusReply(MessagePickupStatusReply),
    MessageDelivery(String),
}

impl MessagePickup {
    /// Sends a Message Pickup 3.0 `Status Request` message
    /// recipient_did : Optional, allows you to ask for status for a specific DID. If none, will ask for default DID in ATM
    /// mediator_did  : Optional, allows you to ask a specific mediator. If none, will ask for default mediator in ATM
    /// wait          : Time Duration to wait for a response from websocket. Default (10 Seconds)
    ///
    /// Returns a StatusReply if successful
    pub async fn send_status_request(
        &self,
        atm: &ATM,
        profile: &Arc<RwLock<Profile>>,
        wait: Option<Duration>,
    ) -> Result<MessagePickupStatusReply, ATMError> {
        let _span = span!(Level::DEBUG, "send_status_request",).entered();
        let _profile = &profile.read().await;
        debug!(
            "Profile ({}): Status Request wait: {:?}",
            _profile.alias, wait
        );

        let (profile_did, mediator_did) = _profile.dids()?;

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let msg = Message::build(
            Uuid::new_v4().into(),
            "https://didcomm.org/messagepickup/3.0/status-request".to_owned(),
            json!({"recipient_did": profile_did}),
        )
        .to(mediator_did.to_string())
        .from(profile_did.to_string())
        .header("return_route".into(), Value::String("all".into()))
        .created_time(now)
        .expires_time(now + 300)
        .finalize();

        let msg_id = msg.id.clone();

        debug!("Status-Request message: {:?}", msg);

        // Pack the message
        let (msg, _) = msg
            .pack_encrypted(
                mediator_did,
                Some(profile_did),
                Some(profile_did),
                &atm.inner.did_resolver,
                &atm.inner.secrets_resolver,
                &PackEncryptedOptions::default(),
            )
            .await
            .map_err(|e| ATMError::MsgSendError(format!("Error packing message: {}", e)))?;

        let response = atm
            .send_message::<EmptyResponse>(profile, &msg, &msg_id)
            .await?;

        self._parse_status_response(&response).await
    }

    pub(crate) async fn _parse_status_response(
        &self,
        message: &Message,
    ) -> Result<MessagePickupStatusReply, ATMError> {
        let status: MessagePickupStatusReply = serde_json::from_value(message.body.clone())
            .map_err(|err| {
                ATMError::MsgReceiveError(format!("Error reading status response: {}", err))
            })?;
        Ok(status)
    }

    /// Sends a Message Pickup 3.0 `Live Delivery` message
    pub async fn toggle_live_delivery(
        &self,
        atm: &ATM,
        profile: &Arc<RwLock<Profile>>,
        live_delivery: bool,
    ) -> Result<(), ATMError> {
        let _span = span!(Level::DEBUG, "toggle_live_delivery",).entered();
        debug!("Setting live_delivery to ({})", live_delivery);
        let _profile = profile.read().await;
        let (profile_did, mediator_did) = _profile.dids()?;

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let msg = Message::build(
            Uuid::new_v4().into(),
            "https://didcomm.org/messagepickup/3.0/live-delivery-change".to_owned(),
            json!({"live_delivery": live_delivery}),
        )
        .header("return_route".into(), Value::String("all".into()))
        .created_time(now)
        .expires_time(now + 300)
        .from(profile_did.into())
        .to(mediator_did.into())
        .finalize();
        let msg_id = msg.id.clone();

        // Pack the message
        let (msg, _) = msg
            .pack_encrypted(
                mediator_did,
                Some(profile_did),
                Some(profile_did),
                &atm.inner.did_resolver,
                &atm.inner.secrets_resolver,
                &PackEncryptedOptions::default(),
            )
            .await
            .map_err(|e| ATMError::MsgSendError(format!("Error packing message: {}", e)))?;

        atm.send_message::<EmptyResponse>(profile, &msg, &msg_id)
            .await?;
        Ok(())
    }

    /// Waits for the next message to be received via websocket live delivery
    /// atm  : The ATM SDK to use
    /// wait : How long to wait (in milliseconds) for a message before returning None
    ///        If 0, will block forever until a message is received
    /// Returns a tuple of the message and metadata, or None if no message was received
    /// NOTE: You still need to delete the message from the server after receiving it
    pub async fn live_stream_next(
        &self,
        atm: &ATM,
        profile: &Arc<RwLock<Profile>>,
        wait: Duration,
    ) -> Result<Option<(Message, Box<UnpackMetadata>)>, ATMError> {
        let _span = span!(Level::DEBUG, "live_stream_next");

        async move {
            // Send the next request to the ws_handler
            atm.inner
                .ws_handler_send_stream
                .send(WsHandlerCommands::Next(profile.clone()))
                .await
                .map_err(|err| {
                    ATMError::TransportError(format!(
                        "Could not send message to ws_handler: {:?}",
                        err
                    ))
                })?;
            debug!("sent next request to ws_handler");

            // Setup the timer for the wait, doesn't do anything till `await` is called in the select! macro
            let sleep: tokio::time::Sleep = tokio::time::sleep(wait);

            let stream = &mut atm.inner.ws_handler_recv_stream.lock().await;
            select! {
                _ = sleep, if wait.as_millis() > 0 => {
                    debug!("Timeout reached, no message received");
                    Ok(None)
                }
                value = stream.recv() => {
                    if let Some(msg) = value {
                        match msg {
                            WsHandlerCommands::MessageReceived(message, meta) => {
                                Ok(Some((message, meta)))
                            }
                            _ => {
                                Err(ATMError::MsgReceiveError("Unexpected message type".into()))
                            }
                        }
                    } else {
                        Ok(None)
                    }
                }
            }
        }
        .instrument(_span)
        .await
    }

    /// Attempts to retrieve a specific message from the server via websocket live delivery
    /// atm  : The ATM SDK to use
    /// msg_id : The ID of the message to retrieve (matches on either `id` or `pthid`)
    /// wait : How long to wait (in milliseconds) for a message before returning None
    ///        If 0, will not block
    /// Returns a tuple of the message and metadata, or None if no message was received
    /// NOTE: You still need to delete the message from the server after receiving it
    pub async fn live_stream_get(
        &self,
        atm: &ATM,
        profile: &Arc<RwLock<Profile>>,
        msg_id: &str,
        wait: Duration,
    ) -> Result<Option<(Message, Box<UnpackMetadata>)>, ATMError> {
        let _span = span!(Level::DEBUG, "live_stream_get");

        async move {
            // Send the get request to the ws_handler
            atm.inner.ws_handler_send_stream
                .send(WsHandlerCommands::Get(profile.clone(), msg_id.to_string()))
                .await
                .map_err(|err| {
                    ATMError::TransportError(format!(
                        "Could not send get message to ws_handler: {:?}",
                        err
                    ))
                })?;
            debug!("sent get request to ws_handler");

            // Setup the timer for the wait, doesn't do anything till `await` is called in the select! macro
            let sleep = tokio::time::sleep(wait);
            tokio::pin!(sleep);

            let stream = &mut atm.inner.ws_handler_recv_stream.lock().await;
            loop {
            select! {
                _ = &mut sleep, if wait.as_millis() > 0 => {
                    debug!("Timeout reached, no message received");
                    atm.inner.ws_handler_send_stream.send(WsHandlerCommands::TimeOut(profile.clone(), msg_id.to_string())).await.map_err(|err| {
                        ATMError::TransportError(format!("Could not send timeout message to ws_handler: {:?}", err))
                    })?;
                    return Ok(None);
                }
                value = stream.recv() => {
                    if let Some(msg) = value {
                        match msg {
                            WsHandlerCommands::MessageReceived(message, meta) => {
                                return Ok(Some((message, meta)));
                            }
                            WsHandlerCommands::NotFound => {
                                // Do nothing, keep waiting
                            }
                            _ => {
                                return Err(ATMError::MsgReceiveError("Unexpected message type".into()));
                            }
                        }
                    } else {
                        return Ok(None);
                    }
                }
            }
        }
    }
        .instrument(_span)
        .await
    }

    /// Sends a Message Pickup 3.0 `Delivery Request` message
    /// atm           : The ATM SDK to use
    /// limit         : # of messages to retrieve, defaults to 10 if None
    pub async fn send_delivery_request(
        &self,
        atm: &ATM,
        profile: &Arc<RwLock<Profile>>,
        limit: Option<usize>,
    ) -> Result<Vec<(Message, UnpackMetadata)>, ATMError> {
        let _span = span!(Level::DEBUG, "send_delivery_request",).entered();
        let _profile = profile.read().await;
        debug!(
            "Profile ({}): Delivery Request limit: {:?}",
            _profile.alias, limit
        );
        let (profile_did, mediator_did) = _profile.dids()?;

        let body = MessagePickupDeliveryRequest {
            recipient_did: profile_did.into(),
            limit: limit.unwrap_or(10),
        };

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let msg = Message::build(
            Uuid::new_v4().into(),
            "https://didcomm.org/messagepickup/3.0/delivery-request".to_owned(),
            serde_json::to_value(body).unwrap(),
        )
        .header("return_route".into(), Value::String("all".into()))
        .to(mediator_did.into())
        .from(profile_did.into())
        .created_time(now)
        .expires_time(now + 300)
        .finalize();

        let msg_id = msg.id.clone();

        debug!("Delivery-Request message: {:?}", msg);

        // Pack the message
        let msg = {
            let (msg, _) = msg
                .pack_encrypted(
                    mediator_did,
                    Some(profile_did),
                    Some(profile_did),
                    &atm.inner.did_resolver,
                    &atm.inner.secrets_resolver,
                    &PackEncryptedOptions::default(),
                )
                .await
                .map_err(|e| ATMError::MsgSendError(format!("Error packing message: {}", e)))?;

            msg
        };

        let response = atm
            .send_message::<EmptyResponse>(profile, &msg, &msg_id)
            .await?;
        self._handle_delivery(atm, &response).await
    }

    /// Iterates through each attachment and unpacks each message into an array to return
    pub(crate) async fn _handle_delivery(
        &self,
        atm: &ATM,
        message: &Message,
    ) -> Result<Vec<(Message, UnpackMetadata)>, ATMError> {
        let mut response: Vec<(Message, UnpackMetadata)> = Vec::new();

        if let Some(attachments) = &message.attachments {
            for attachment in attachments {
                match &attachment.data {
                    AttachmentData::Base64 { value } => {
                        let decoded = match BASE64_URL_SAFE_NO_PAD.decode(value.base64.clone()) {
                            Ok(decoded) => match String::from_utf8(decoded) {
                                Ok(decoded) => decoded,
                                Err(e) => {
                                    warn!(
                                            "Error encoding vec[u8] to string: ({:?}). Attachment ID ({:?})",
                                            e, attachment.id
                                        );
                                    continue;
                                }
                            },
                            Err(e) => {
                                warn!(
                                    "Error decoding base64: ({:?}). Attachment ID ({:?})",
                                    e, attachment.id
                                );
                                continue;
                            }
                        };

                        match atm.unpack(&decoded).await {
                            Ok((mut m, u)) => {
                                if let Some(attachment_id) = &attachment.id {
                                    m.id = attachment_id.to_string();
                                }
                                response.push((m, u))
                            }
                            Err(e) => {
                                warn!("Error unpacking message: ({:?})", e);
                                continue;
                            }
                        };
                    }
                    _ => {
                        warn!("Attachment type not supported: {:?}", attachment.data);
                        continue;
                    }
                };
            }
        }

        Ok(response)
    }

    /// Sends a Message Pickup 3.0 `Messages Received` message
    /// This effectively deletes the messages from the server
    /// atm           : The ATM SDK to use
    /// list          : List of messages to delete (message ID's)
    ///
    /// A status reply will be returned if successful
    pub async fn send_messages_received(
        &self,
        atm: &ATM,
        profile: &Arc<RwLock<Profile>>,
        list: &Vec<String>,
    ) -> Result<MessagePickupStatusReply, ATMError> {
        let _span = span!(Level::DEBUG, "send_messages_received",).entered();
        let _profile = profile.read().await;
        debug!(
            "Profile ({}): Messages Received, # msgs to delete: {}",
            _profile.alias,
            list.len()
        );

        let (profile_did, mediator_did) = _profile.dids()?;

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let msg = Message::build(
            Uuid::new_v4().into(),
            "https://didcomm.org/messagepickup/3.0/messages-received".to_owned(),
            json!({"message_id_list": list}),
        )
        .header("return_route".into(), Value::String("all".into()))
        .to(mediator_did.into())
        .from(profile_did.into())
        .created_time(now)
        .expires_time(now + 300)
        .finalize();

        let msg_id = msg.id.clone();

        debug!("messages-received message: {:?}", msg);

        // Pack the message
        let (msg, _) = msg
            .pack_encrypted(
                mediator_did,
                Some(profile_did),
                Some(profile_did),
                &atm.inner.did_resolver,
                &atm.inner.secrets_resolver,
                &PackEncryptedOptions::default(),
            )
            .await
            .map_err(|e| ATMError::MsgSendError(format!("Error packing message: {}", e)))?;

        let response = atm
            .send_message::<EmptyResponse>(profile, &msg, &msg_id)
            .await?;
        self._parse_status_response(&response).await
    }
}
