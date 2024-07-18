use std::time::{Duration, SystemTime};

use atn_atm_didcomm::{Message, PackEncryptedOptions, UnpackMetadata};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::select;
use tracing::{debug, span, Instrument, Level};
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

impl MessagePickup {
    /// Sends a Message Pickup 3.0 `Status Request` message
    /// atm           : The ATM SDK to use
    /// recipient_did : Optional, allows you to ask for status for a specific DID. If none, will ask for default DID in ATM
    /// mediator_did  : Optional, allows you to ask a specific mediator. If none, will ask for default mediator in ATM
    pub async fn send_status_request<'c>(
        &self,
        atm: &'c mut ATM<'_>,
        recipient_did: Option<String>,
        mediator_did: Option<String>,
    ) -> Result<SendMessageResponse<MessagePickupStatusReply>, ATMError> {
        let _span = span!(Level::DEBUG, "send_status_request",).entered();
        debug!(
            "Status Request to recipient_did: {:?}, mediator_did: {:?}",
            recipient_did, mediator_did
        );

        // Check that DID(s) exist in DIDResolver, add it if not
        if let Some(recipient_did) = &recipient_did {
            if !atm.did_resolver.contains(recipient_did) {
                debug!(
                    "Recipient DID ({}) not found in resolver, adding...",
                    recipient_did
                );
                atm.add_did(recipient_did).await?;
            }
        }
        if let Some(mediator_did) = &mediator_did {
            if !atm.did_resolver.contains(mediator_did) {
                debug!(
                    "Mediator DID ({}) not found in resolver, adding...",
                    mediator_did
                );
                atm.add_did(mediator_did).await?;
            }
        }

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
            atm.ws_send_didcomm_message(&msg, &msg_id).await
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
                let (unpacked, _) = atm.unpack(&message).await?;
                debug!("Good ({})", unpacked.body);
                let status: MessagePickupStatusReply = serde_json::from_value(unpacked.body)
                    .map_err(|err| {
                        ATMError::MsgSendError(format!("Error unpacking response: {}", err))
                    })?;
                Ok(SendMessageResponse::RestAPI(Some(status)))
            } else {
                Err(ATMError::MsgSendError("No response from API".into()))
            }
        }
    }

    pub async fn toggle_live_delivery<'c>(
        &self,
        atm: &'c mut ATM<'_>,
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
    pub async fn live_stream_next<'c>(
        &self,
        atm: &'c mut ATM<'_>,
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
    pub async fn live_stream_get<'c>(
        &self,
        atm: &'c mut ATM<'_>,
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
}
