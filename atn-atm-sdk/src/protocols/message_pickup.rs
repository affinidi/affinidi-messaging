use std::time::SystemTime;

use atn_atm_didcomm::{Message, PackEncryptedOptions};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::{debug, span, Level};
use uuid::Uuid;

use crate::{
    errors::ATMError,
    messages::{sending::InboundMessageResponse, EmptyResponse, GenericDataStruct},
    transports::SendMessageResponse,
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
}
