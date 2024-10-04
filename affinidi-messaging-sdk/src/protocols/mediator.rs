//! Handles mediator configuration and administration tasks
//! Admin account management
//! Global ACL management

use std::time::{Duration, SystemTime};

use affinidi_messaging_didcomm::{Message, PackEncryptedOptions};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{debug, span, Instrument, Level};
use uuid::Uuid;

use crate::{
    errors::ATMError,
    messages::{known::MessageType, sending::InboundMessageResponse, EmptyResponse},
    protocols::message_pickup::MessagePickup,
    transports::SendMessageResponse,
    ATM,
};
#[derive(Default)]
pub struct Mediator {}

#[derive(Serialize, Deserialize)]
pub enum MediatorAdminRequest {
    AdminAdd(Vec<String>),
    AdminRemove(Vec<String>),
    AdminList { cursor: u32, limit: u32 },
}
/// A list of admins in the mediator
/// - `admins` - The list of admins (SHA256 Hashed DIDs)
/// - `next` - The offset to use for the next request
#[derive(Serialize, Deserialize)]
pub struct MediatorAdminList {
    pub admins: Vec<String>,
    pub cursor: u32,
}

impl Mediator {
    /// Parses the response from the mediator for a list of admins
    fn _parse_list_admins_response(
        &self,
        message: &Message,
    ) -> Result<MediatorAdminList, ATMError> {
        serde_json::from_value(message.body.clone()).map_err(|err| {
            ATMError::MsgReceiveError(format!(
                "Mediator Admin List response could not be parsed. Reason: {}",
                err
            ))
        })
    }
    /// Lists all the admins in the mediator
    /// - `atm` - The ATM client to use
    /// - `cursor` - The cursor to start from (Defaults to 0 if not provided)
    /// - `limit` - The maximum number of admins to return (Defaults to 100 if not provided)
    /// # Returns
    /// A list of admins in the mediator
    pub async fn list_admins(
        &self,
        atm: &mut ATM<'_>,
        cursor: Option<u32>,
        limit: Option<u32>,
    ) -> Result<MediatorAdminList, ATMError> {
        let _span = span!(Level::DEBUG, "list_admins");

        async move {
            debug!(
                "Requesting list of Admin accounts from mediator. Cursor: {} Limit: {}",
                cursor.unwrap_or(0),
                limit.unwrap_or(100)
            );

            let mediator_did = if let Some(mediator_did) = &atm.config.atm_did {
                mediator_did.to_string()
            } else {
                return Err(ATMError::ConfigError(
                    "You must provide the DID for the ATM service!".to_owned(),
                ));
            };

            let my_did = if let Some(my_did) = &atm.config.my_did {
                my_did.to_string()
            } else {
                return Err(ATMError::ConfigError(
                    "You must provide a DID for the SDK, used for authentication!".to_owned(),
                ));
            };

            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let msg = Message::build(
                Uuid::new_v4().into(),
                "https://didcomm.org/mediator/1.0/admin-management".to_owned(),
                json!({"AdminList": {"cursor": cursor.unwrap_or(0), "limit": limit.unwrap_or(100)}}),
            )
            .to(mediator_did.clone())
            .from(my_did.clone())
            .created_time(now)
            .expires_time(now + 10)
            .finalize();

            let msg_id = msg.id.clone();

            // Pack the message
            let (msg, _) = msg
                .pack_encrypted(
                    &mediator_did,
                    Some(&my_did),
                    Some(&my_did),
                    &atm.did_resolver,
                    &atm.secrets_resolver,
                    &PackEncryptedOptions::default(),
                )
                .await
                .map_err(|e| ATMError::MsgSendError(format!("Error packing message: {}", e)))?;

            let pickup = MessagePickup::default();
            let message = if atm.ws_send_stream.is_some() {
                atm.ws_send_didcomm_message::<EmptyResponse>(&msg, &msg_id)
                    .await?;
                let response = pickup
                    .live_stream_get(atm, &msg_id, Duration::from_secs(10))
                    .await?;

                if let Some((message, _)) = response {
                    message
                } else {
                    return Err(ATMError::MsgSendError("No response from API".into()));
                }
            } else {
                let a = atm
                    .send_didcomm_message::<InboundMessageResponse>(&msg, true)
                    .await?;

                debug!("Response: {:?}", a);

                // Unpack the response
                if let SendMessageResponse::RestAPI(Some(InboundMessageResponse::Ephemeral(
                    message,
                ))) = a
                {
                    let (message, _) = atm.unpack(&message).await?;
                    message
                } else {
                    return Err(ATMError::MsgSendError("No response from API".into()));
                }
            };

            let type_ = message.type_.parse::<MessageType>()?;
            if let MessageType::ProblemReport = type_ {
                Err(ATMError::from_problem_report(&message))
            } else {
                self._parse_list_admins_response(&message)
            }
        }
        .instrument(_span)
        .await
    }
}
