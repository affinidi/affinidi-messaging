use atn_atm_didcomm::{AttachmentData, Message, PackEncryptedOptions, UnpackMetadata};
use base64::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::{Duration, SystemTime};
use tokio::select;
use tracing::{debug, span, warn, Instrument, Level};
use uuid::Uuid;

use crate::{
    errors::ATMError,
    messages::{sending::InboundMessageResponse, EmptyResponse, GenericDataStruct},
    transports::SendMessageResponse,
    websockets::ws_handler::WSCommand,
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
        atm: &mut ATM<'_>,
        recipient_did: Option<String>,
        mediator_did: Option<String>,
        wait: Option<Duration>,
    ) -> Result<MessagePickupStatusReply, ATMError> {
        let _span = span!(Level::DEBUG, "send_status_request",).entered();
        debug!(
            "Status Request to recipient_did: {:?}, mediator_did: {:?}, wait: {:?}",
            recipient_did, mediator_did, wait
        );

        let mut msg = Message::build(
            Uuid::new_v4().into(),
            "https://didcomm.org/messagepickup/3.0/status-request".to_owned(),
            json!({}),
        )
        .header("return_route".into(), Value::String("all".into()));

        if let Some(recipient_did) = &recipient_did {
            msg = msg.body(json!({"recipient_did": recipient_did}));
        }

        let to_did = if let Some(mediator_did) = mediator_did {
            mediator_did
        } else {
            atm.config.atm_did.clone()
        };
        msg = msg.to(to_did.clone());

        msg = msg.from(atm.config.my_did.clone());
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let msg = msg.created_time(now).expires_time(now + 300).finalize();
        let msg_id = msg.id.clone();

        debug!("Status-Request message: {:?}", msg);

        // Pack the message
        let (msg, _) = msg
            .pack_encrypted(
                &to_did,
                Some(&atm.config.my_did),
                Some(&atm.config.my_did),
                &atm.did_resolver,
                &atm.secrets_resolver,
                &PackEncryptedOptions::default(),
            )
            .await
            .map_err(|e| ATMError::MsgSendError(format!("Error packing message: {}", e)))?;

        if atm.ws_send_stream.is_some() {
            atm.ws_send_didcomm_message::<EmptyResponse>(&msg, &msg_id)
                .await?;
            let response = self
                .live_stream_get(
                    atm,
                    &msg_id,
                    wait.unwrap_or_else(|| Duration::from_secs(10)),
                )
                .await?;

            if let Some((message, _)) = response {
                self._parse_status_response(&message).await
            } else {
                Err(ATMError::MsgSendError("No response from API".into()))
            }
        } else {
            type MessageString = String;
            impl GenericDataStruct for MessageString {}

            let a = atm
                .send_didcomm_message::<InboundMessageResponse>(&msg, true)
                .await?;

            debug!("Response: {:?}", a);

            // Unpack the response
            if let SendMessageResponse::RestAPI(Some(InboundMessageResponse::Ephemeral(message))) =
                a
            {
                let (message, _) = atm.unpack(&message).await?;
                self._parse_status_response(&message).await
            } else {
                Err(ATMError::MsgSendError("No response from API".into()))
            }
        }
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
        atm: &mut ATM<'_>,
        live_delivery: bool,
    ) -> Result<(), ATMError> {
        let _span = span!(Level::DEBUG, "toggle_live_delivery",).entered();
        debug!("Setting live_delivery to ({})", live_delivery);

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
        .from(atm.config.my_did.clone())
        .to(atm.config.atm_did.clone())
        .finalize();
        let msg_id = msg.id.clone();

        // Pack the message
        let (msg, _) = msg
            .pack_encrypted(
                &atm.config.atm_did,
                Some(&atm.config.my_did),
                Some(&atm.config.my_did),
                &atm.did_resolver,
                &atm.secrets_resolver,
                &PackEncryptedOptions::default(),
            )
            .await
            .map_err(|e| ATMError::MsgSendError(format!("Error packing message: {}", e)))?;

        if atm.ws_send_stream.is_some() {
            atm.ws_send_didcomm_message::<EmptyResponse>(&msg, &msg_id)
                .await?;
        } else {
            atm.send_didcomm_message::<InboundMessageResponse>(&msg, true)
                .await?;
        }
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
        atm: &mut ATM<'_>,
        wait: Duration,
    ) -> Result<Option<(Message, Box<UnpackMetadata>)>, ATMError> {
        let _span = span!(Level::DEBUG, "live_stream_next");

        async move {
            let binding = atm.ws_recv_stream.as_mut();
            let stream = if let Some(stream) = binding {
                stream
            } else {
                return Err(ATMError::TransportError("No websocket recv stream".into()));
            };

            // Send the next request to the ws_handler
            if let Some(tx_stream) = &atm.ws_send_stream {
                tx_stream.send(WSCommand::Next).await.map_err(|err| {
                    ATMError::TransportError(format!(
                        "Could not send message to ws_handler: {:?}",
                        err
                    ))
                })?;
                debug!("sent next request to ws_handler");
            } else {
                return Err(ATMError::TransportError("No websocket send stream".into()));
            }

            // Setup the timer for the wait, doesn't do anything till `await` is called in the select! macro
            let sleep: tokio::time::Sleep = tokio::time::sleep(wait);

            select! {
                _ = sleep, if wait.as_millis() > 0 => {
                    debug!("Timeout reached, no message received");
                    Ok(None)
                }
                value = stream.recv() => {
                    if let Some(msg) = value {
                        match msg {
                            WSCommand::MessageReceived(message, meta) => {
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
        atm: &mut ATM<'_>,
        msg_id: &str,
        wait: Duration,
    ) -> Result<Option<(Message, Box<UnpackMetadata>)>, ATMError> {
        let _span = span!(Level::DEBUG, "live_stream_get");

        async move {
            let binding = atm.ws_recv_stream.as_mut();
            let stream = if let Some(stream) = binding {
                stream
            } else {
                return Err(ATMError::TransportError("No websocket stream".into()));
            };

            // Send the get request to the ws_handler
            let tx_stream = if let Some(tx_stream) = &atm.ws_send_stream {
                tx_stream
                    .send(WSCommand::Get(msg_id.to_string()))
                    .await
                    .map_err(|err| {
                        ATMError::TransportError(format!(
                            "Could not send get message to ws_handler: {:?}",
                            err
                        ))
                    })?;
                debug!("sent get request to ws_handler");
                tx_stream
            } else {
                return Err(ATMError::TransportError("No websocket send stream".into()));
            };

            // Setup the timer for the wait, doesn't do anything till `await` is called in the select! macro
            let sleep = tokio::time::sleep(wait);
            tokio::pin!(sleep);

            loop {
            select! {
                _ = &mut sleep, if wait.as_millis() > 0 => {
                    debug!("Timeout reached, no message received");
                    tx_stream.send(WSCommand::TimeOut(msg_id.to_string())).await.map_err(|err| {
                        ATMError::TransportError(format!("Could not send timeout message to ws_handler: {:?}", err))
                    })?;
                    return Ok(None);
                }
                value = stream.recv() => {
                    if let Some(msg) = value {
                        match msg {
                            WSCommand::MessageReceived(message, meta) => {
                                return Ok(Some((message, meta)));
                            }
                            WSCommand::NotFound => {
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
    /// recipient_did : Optional, allows you to ask for status for a specific DID. If none, will ask for default DID in ATM
    /// mediator_did  : Optional, allows you to ask a specific mediator. If none, will ask for default mediator in ATM
    /// limit         : # of messages to retrieve, defaults to 10 if None
    /// wait          : Time Duration to wait for a response from websocket. Default (10 Seconds)
    pub async fn send_delivery_request(
        &self,
        atm: &mut ATM<'_>,
        recipient_did: Option<String>,
        mediator_did: Option<String>,
        limit: Option<usize>,
        wait: Option<Duration>,
    ) -> Result<Vec<(Message, UnpackMetadata)>, ATMError> {
        let _span = span!(Level::DEBUG, "send_delivery_request",).entered();
        debug!(
            "Delivery Request for recipient_did: {:?}, mediator_did: {:?} limit: {:?}",
            recipient_did, mediator_did, limit
        );

        let body = MessagePickupDeliveryRequest {
            recipient_did: if let Some(recipient) = recipient_did {
                recipient
            } else {
                atm.config.my_did.clone()
            },
            limit: if let Some(limit) = limit { limit } else { 10 },
        };

        let mut msg = Message::build(
            Uuid::new_v4().into(),
            "https://didcomm.org/messagepickup/3.0/delivery-request".to_owned(),
            serde_json::to_value(body).unwrap(),
        )
        .header("return_route".into(), Value::String("all".into()));

        let to_did = if let Some(mediator_did) = mediator_did {
            mediator_did
        } else {
            atm.config.atm_did.clone()
        };
        msg = msg.to(to_did.clone());

        msg = msg.from(atm.config.my_did.clone());
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let msg = msg.created_time(now).expires_time(now + 300).finalize();
        let msg_id = msg.id.clone();

        debug!("Delivery-Request message: {:?}", msg);

        // Pack the message
        let (msg, _) = msg
            .pack_encrypted(
                &to_did,
                Some(&atm.config.my_did),
                Some(&atm.config.my_did),
                &atm.did_resolver,
                &atm.secrets_resolver,
                &PackEncryptedOptions::default(),
            )
            .await
            .map_err(|e| ATMError::MsgSendError(format!("Error packing message: {}", e)))?;

        if atm.ws_send_stream.is_some() {
            let wait_duration = if let Some(wait) = wait {
                wait
            } else {
                Duration::from_secs(10)
            };

            atm.ws_send_didcomm_message::<EmptyResponse>(&msg, &msg_id)
                .await?;

            if let Some((message, _)) = self.live_stream_get(atm, &msg_id, wait_duration).await? {
                debug!("unpacked: {:#?}", message);
            }

            // wait for the response from the server
            let message = self
                .live_stream_get(
                    atm,
                    &msg_id,
                    wait.unwrap_or_else(|| Duration::from_secs(10)),
                )
                .await?;

            if let Some((message, _)) = message {
                self._handle_delivery(atm, &message).await
            } else {
                Err(ATMError::MsgSendError("No response from API".into()))
            }
        } else {
            let a = atm
                .send_didcomm_message::<InboundMessageResponse>(&msg, true)
                .await?;

            debug!("Response: {:?}", a);

            // Unpack the response
            if let SendMessageResponse::RestAPI(Some(InboundMessageResponse::Ephemeral(message))) =
                a
            {
                let (unpacked, _) = atm.unpack(&message).await?;

                debug!("unpacked: {:#?}", unpacked);

                self._handle_delivery(atm, &unpacked).await
            } else {
                Err(ATMError::MsgSendError("No response from API".into()))
            }
        }
    }

    /// Iterates through each attachment and unpacks each message into an array to return
    pub(crate) async fn _handle_delivery(
        &self,
        atm: &mut ATM<'_>,
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
                            Ok((m, u)) => response.push((m, u)),
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
    /// recipient_did : Optional, allows you to ask for status for a specific DID. If none, will ask for default DID in ATM
    /// mediator_did  : Optional, allows you to ask a specific mediator. If none, will ask for default mediator in ATM
    /// list          : List of messages to delete (message ID's)
    /// wait          : Time Duration to wait for a response from websocket. Default (10 Seconds)
    ///
    /// A status reply will be returned if successful
    pub async fn send_messages_received(
        &self,
        atm: &mut ATM<'_>,
        recipient_did: Option<String>,
        mediator_did: Option<String>,
        list: &Vec<String>,
        wait: Option<Duration>,
    ) -> Result<MessagePickupStatusReply, ATMError> {
        let _span = span!(Level::DEBUG, "send_messages_received",).entered();
        debug!(
            "Messages Received for recipient_did: {:?}, mediator_did: {:?}, # msgs to delete: {}",
            recipient_did,
            mediator_did,
            list.len()
        );

        let mut msg = Message::build(
            Uuid::new_v4().into(),
            "https://didcomm.org/messagepickup/3.0/delivery-request".to_owned(),
            json!({"message_id_list": list}),
        )
        .header("return_route".into(), Value::String("all".into()));

        let to_did = if let Some(mediator_did) = mediator_did {
            mediator_did
        } else {
            atm.config.atm_did.clone()
        };
        msg = msg.to(to_did.clone());

        msg = msg.from(atm.config.my_did.clone());
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let msg = msg.created_time(now).expires_time(now + 300).finalize();
        let msg_id = msg.id.clone();

        debug!("Delivery-Request message: {:?}", msg);

        // Pack the message
        let (msg, _) = msg
            .pack_encrypted(
                &to_did,
                Some(&atm.config.my_did),
                Some(&atm.config.my_did),
                &atm.did_resolver,
                &atm.secrets_resolver,
                &PackEncryptedOptions::default(),
            )
            .await
            .map_err(|e| ATMError::MsgSendError(format!("Error packing message: {}", e)))?;

        if atm.ws_send_stream.is_some() {
            let wait_duration = if let Some(wait) = wait {
                wait
            } else {
                Duration::from_secs(10)
            };

            atm.ws_send_didcomm_message::<EmptyResponse>(&msg, &msg_id)
                .await?;

            if let Some((message, _)) = self.live_stream_get(atm, &msg_id, wait_duration).await? {
                debug!("unpacked: {:#?}", message);
            }

            // wait for the response from the server
            let message = self
                .live_stream_get(
                    atm,
                    &msg_id,
                    wait.unwrap_or_else(|| Duration::from_secs(10)),
                )
                .await?;

            if let Some((message, _)) = message {
                self._parse_status_response(&message).await
            } else {
                Err(ATMError::MsgSendError("No response from API".into()))
            }
        } else {
            let a = atm
                .send_didcomm_message::<InboundMessageResponse>(&msg, true)
                .await?;

            debug!("Response: {:?}", a);

            // Unpack the response
            if let SendMessageResponse::RestAPI(Some(InboundMessageResponse::Ephemeral(message))) =
                a
            {
                let (message, _) = atm.unpack(&message).await?;

                debug!("unpacked: {:#?}", message);

                self._parse_status_response(&message).await
            } else {
                Err(ATMError::MsgSendError("No response from API".into()))
            }
        }
    }
}
