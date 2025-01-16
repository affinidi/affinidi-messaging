/*!
 * DIDComm handling for ACLs
 */

use std::{sync::Arc, time::SystemTime};

use affinidi_messaging_didcomm::{Message, PackEncryptedOptions};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{debug, span, Instrument, Level};
use uuid::Uuid;

use crate::{errors::ATMError, profiles::Profile, transports::SendMessageResponse, ATM};

use super::{
    acls::{ACLModeType, MediatorACLSet},
    administration::Mediator,
};

/// Used in lists to show DID Hash and ACLs
#[derive(Debug, Serialize, Deserialize)]
pub struct MediatorACLExpanded {
    pub did_hash: String,
    pub acl_value: String,
    pub acls: MediatorACLSet,
}
/// DIDComm message body for requesting ACLs for a list of DID Hashes
#[derive(Serialize, Deserialize)]
pub enum MediatorACLRequest {
    #[serde(rename = "acl_get")]
    GetACL(Vec<String>),
}

/// DIDComm message body for responding with a set of ACLs for a list of DID Hashes
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "acl_response")]
pub struct MediatorACLResponse {
    pub acl_response: Vec<MediatorACLExpanded>,
    pub mediator_acl_mode: ACLModeType,
}

impl Mediator {
    /// Parses the response from the mediator for ACL Get
    fn _parse_acls_get_response(&self, message: &Message) -> Result<MediatorACLResponse, ATMError> {
        serde_json::from_value(message.body.clone()).map_err(|err| {
            ATMError::MsgReceiveError(format!(
                "Mediator ACL get response could not be parsed. Reason: {}",
                err
            ))
        })
    }

    /// Get the ACL's set for a list of DIDs
    pub async fn acls_get(
        &self,
        atm: &ATM,
        profile: &Arc<Profile>,
        dids: &Vec<String>,
    ) -> Result<MediatorACLResponse, ATMError> {
        let _span = span!(Level::DEBUG, "acls_get");

        async move {
            debug!("Requesting ACLs for DIDs: {:?}", dids);

            let (profile_did, mediator_did) = profile.dids()?;

            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let msg = Message::build(
                Uuid::new_v4().into(),
                "https://didcomm.org/mediator/1.0/acl-management".to_owned(),
                json!({"acl_get": dids}),
            )
            .to(mediator_did.into())
            .from(profile_did.into())
            .created_time(now)
            .expires_time(now + 10)
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

            if let SendMessageResponse::Message(message) =
                atm.send_message(profile, &msg, &msg_id, true, true).await?
            {
                self._parse_acls_get_response(&message)
            } else {
                Err(ATMError::MsgReceiveError(
                    "No response from mediator".to_owned(),
                ))
            }
        }
        .instrument(_span)
        .await
    }
}
