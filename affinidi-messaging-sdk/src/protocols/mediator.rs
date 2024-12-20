//! Handles mediator configuration and administration tasks
//! Admin account management
//! Global ACL management

use crate::{errors::ATMError, profiles::Profile, transports::SendMessageResponse, ATM};
use affinidi_messaging_didcomm::{Message, PackEncryptedOptions};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha256::digest;
use std::{sync::Arc, time::SystemTime};
use tracing::{debug, span, Instrument, Level};
use uuid::Uuid;
#[derive(Default)]
pub struct Mediator {}

#[derive(Serialize, Deserialize)]
pub enum MediatorAdminRequest {
    AdminAdd(Vec<String>),
    AdminRemove(Vec<String>),
    AdminList { cursor: u32, limit: u32 },
    AccountList { cursor: u32, limit: u32 },
    AccountAdd(String),
    AccountRemove(String),
    Configuration(Value),
}

/// A list of admins in the mediator
/// - `admins` - The list of admins (SHA256 Hashed DIDs)
/// - `next` - The offset to use for the next request
#[derive(Serialize, Deserialize)]
pub struct MediatorAdminList {
    pub accounts: Vec<String>,
    pub cursor: u32,
}

pub type MediatorAccountList = MediatorAdminList;

impl Mediator {
    pub async fn get_config(&self, atm: &ATM, profile: &Arc<Profile>) -> Result<Value, ATMError> {
        let _span = span!(Level::DEBUG, "get_config");

        async move {
            let (profile_did, mediator_did) = profile.dids()?;

            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let msg = Message::build(
                Uuid::new_v4().into(),
                "https://didcomm.org/mediator/1.0/admin-management".to_owned(),
                json!({"Configuration": {}}),
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
                atm.send_message(profile, &msg, &msg_id, true).await?
            {
                Ok(message.body)
            } else {
                Err(ATMError::MsgReceiveError(
                    "No response from mediator".to_owned(),
                ))
            }
        }
        .instrument(_span)
        .await
    }

    /// Parses the response from the mediator for Adding admins
    fn _parse_add_admins_response(&self, message: &Message) -> Result<i32, ATMError> {
        serde_json::from_value(message.body.clone()).map_err(|err| {
            ATMError::MsgReceiveError(format!(
                "Mediator Admin Add response could not be parsed. Reason: {}",
                err
            ))
        })
    }

    /// Adds a number of admins to the mediator
    /// - `atm` - The ATM client to use
    /// - `admins` - Array of Strings representing the DIDs of the admins to add (can be SHA256 or raw DID)
    ///   NOTE: `admins` is limited to 100 elements
    /// # Returns
    /// Success: Number of admins added to the mediator
    /// Error: An error message
    pub async fn add_admins(
        &self,
        atm: &ATM,
        profile: &Arc<Profile>,
        admins: &[String],
    ) -> Result<i32, ATMError> {
        let _span = span!(Level::DEBUG, "add_admins");

        async move {
            debug!(
                "Adding admin accounts to mediator: count {:?}",
                admins.len()
            );

            if admins.len() > 100 {
                return Err(ATMError::ConfigError(
                    "You can only add up to 100 admins at a time!".to_owned(),
                ));
            }

            let (profile_did, mediator_did) = profile.dids()?;

            let mut digests: Vec<String> = Vec::new();
            let re = Regex::new(r"[0-9a-f]{64}").unwrap();
            for admin in admins {
                if re.is_match(admin) {
                    digests.push(admin.clone());
                } else if admin.starts_with("did:") {
                    digests.push(digest(admin));
                } else {
                    return Err(ATMError::ConfigError(
                        format!(
                            "Admins ({}) doesn't seem to be a SHA256 hash or a DID!",
                            admin
                        )
                        .to_owned(),
                    ));
                }
            }

            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let msg = Message::build(
                Uuid::new_v4().into(),
                "https://didcomm.org/mediator/1.0/admin-management".to_owned(),
                json!({"AdminAdd": digests}),
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
                atm.send_message(profile, &msg, &msg_id, true).await?
            {
                self._parse_add_admins_response(&message)
            } else {
                Err(ATMError::MsgReceiveError(
                    "No response from mediator".to_owned(),
                ))
            }
        }
        .instrument(_span)
        .await
    }

    /// Parses the response from the mediator for Removing admins
    fn _parse_remove_admins_response(&self, message: &Message) -> Result<i32, ATMError> {
        serde_json::from_value(message.body.clone()).map_err(|err| {
            ATMError::MsgReceiveError(format!(
                "Mediator Admin Remove response could not be parsed. Reason: {}",
                err
            ))
        })
    }

    /// Removes a number of admins from the mediator
    /// - `atm` - The ATM client to use
    /// - `admins` - Array of Strings representing the SHA256 Hashed DIDs of the admins to remove
    ///   NOTE: `admins` is limited to 100 elements
    /// # Returns
    /// Success: Number of admins removed from the mediator
    /// Error: An error message
    pub async fn remove_admins(
        &self,
        atm: &ATM,
        profile: &Arc<Profile>,
        admins: &[String],
    ) -> Result<i32, ATMError> {
        let _span = span!(Level::DEBUG, "remove_admins");

        async move {
            debug!(
                "Removing admin accounts from mediator: count {:?}",
                admins.len()
            );

            if admins.len() > 100 {
                return Err(ATMError::ConfigError(
                    "You can only remove up to 100 admins at a time!".to_owned(),
                ));
            }

            let (profile_did, mediator_did) = profile.dids()?;

            // Check that these are digests
            let re = Regex::new(r"[0-9a-f]{64}").unwrap();
            for admin in admins {
                if !re.is_match(admin) {
                    return Err(ATMError::ConfigError(
                        "Admins must be SHA256 Hashed DIDs!".to_owned(),
                    ));
                }
            }

            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let msg = Message::build(
                Uuid::new_v4().into(),
                "https://didcomm.org/mediator/1.0/admin-management".to_owned(),
                json!({"AdminRemove": admins}),
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
                atm.send_message(profile, &msg, &msg_id, true).await?
            {
                self._parse_remove_admins_response(&message)
            } else {
                Err(ATMError::MsgReceiveError(
                    "No response from mediator".to_owned(),
                ))
            }
        }
        .instrument(_span)
        .await
    }

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
        atm: &ATM,
        profile: &Arc<Profile>,
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

            let (profile_did, mediator_did) = profile.dids()?;

            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let msg = Message::build(
                Uuid::new_v4().into(),
                "https://didcomm.org/mediator/1.0/admin-management".to_owned(),
                json!({"AdminList": {"cursor": cursor.unwrap_or(0), "limit": limit.unwrap_or(100)}}),
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

                if let SendMessageResponse::Message(message) = atm
                .send_message(profile, &msg, &msg_id, true)
                .await? {
                self._parse_list_admins_response(&message)
                } else {
                    Err(ATMError::MsgReceiveError(
                        "No response from mediator".to_owned(),
                    ))
                }
        }
        .instrument(_span)
        .await
    }

    /// Parses the response from the mediator for a list of accounts
    fn _parse_list_accounts_response(
        &self,
        message: &Message,
    ) -> Result<MediatorAccountList, ATMError> {
        serde_json::from_value(message.body.clone()).map_err(|err| {
            ATMError::MsgReceiveError(format!(
                "Mediator Account List response could not be parsed. Reason: {}",
                err
            ))
        })
    }

    /// Lists known DID accounts in the mediator
    /// - `atm` - The ATM client to use
    /// - `cursor` - The cursor to start from (Defaults to 0 if not provided)
    /// - `limit` - The maximum number of accounts to return (Defaults to 100 if not provided)
    /// # Returns
    /// A list of DID Accounts in the mediator
    /// NOTE: This will also include the admin accounts
    pub async fn list_accounts(
        &self,
        atm: &ATM,
        profile: &Arc<Profile>,
        cursor: Option<u32>,
        limit: Option<u32>,
    ) -> Result<MediatorAccountList, ATMError> {
        let _span = span!(Level::DEBUG, "list_accounts");

        async move {
            debug!(
                "Requesting list of accounts from mediator. Cursor: {} Limit: {}",
                cursor.unwrap_or(0),
                limit.unwrap_or(100)
            );

            let (profile_did, mediator_did) = profile.dids()?;

            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let msg = Message::build(
                Uuid::new_v4().into(),
                "https://didcomm.org/mediator/1.0/admin-management".to_owned(),
                json!({"AccountList": {"cursor": cursor.unwrap_or(0), "limit": limit.unwrap_or(100)}}),
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

                if let SendMessageResponse::Message(message) = atm
                .send_message(profile, &msg, &msg_id, true)
                .await? {
                self._parse_list_accounts_response(&message)
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
