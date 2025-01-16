use affinidi_messaging_didcomm::{Message, PackEncryptedOptions};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha256::digest;
use tracing::{debug, span, Instrument, Level};
use uuid::Uuid;

use super::{acls::MediatorACLSet, administration::Mediator};
use crate::{errors::ATMError, profiles::Profile, transports::SendMessageResponse, ATM};
use std::{
    fmt::{self, Display, Formatter},
    sync::Arc,
    time::SystemTime,
};

#[derive(Serialize, Deserialize)]
pub enum MediatorAccountRequest {
    AccountGet(String),
    AccountList { cursor: u32, limit: u32 },
    AccountAdd { did_hash: String, acls: Option<u64> },
    AccountRemove(String),
}

/// Different levels of accounts in the mediator
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub enum AccountType {
    RootAdmin,
    Admin,
    #[default]
    Standard,
    Unknown,
}

impl Display for AccountType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            AccountType::RootAdmin => write!(f, "Root Admin"),
            AccountType::Admin => write!(f, "Admin"),
            AccountType::Standard => write!(f, "Standard"),
            AccountType::Unknown => write!(f, "Unknown"),
        }
    }
}

impl From<&str> for AccountType {
    fn from(role_type: &str) -> Self {
        match role_type {
            "0" => AccountType::Standard,
            "1" => AccountType::Admin,
            "2" => AccountType::RootAdmin,
            _ => AccountType::Unknown,
        }
    }
}

impl From<u32> for AccountType {
    fn from(role_type: u32) -> Self {
        match role_type {
            0 => AccountType::Standard,
            1 => AccountType::Admin,
            2 => AccountType::RootAdmin,
            _ => AccountType::Unknown,
        }
    }
}

impl From<String> for AccountType {
    fn from(role_type: String) -> Self {
        role_type.as_str().into()
    }
}

impl From<AccountType> for String {
    fn from(role_type: AccountType) -> Self {
        match role_type {
            AccountType::RootAdmin => "2".to_owned(),
            AccountType::Admin => "1".to_owned(),
            AccountType::Standard => "0".to_owned(),
            AccountType::Unknown => "-1".to_owned(),
        }
    }
}

/// An account in the mediator
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Account {
    pub did_hash: String,
    pub acls: u64,
    pub _type: AccountType,
}

#[derive(Serialize, Deserialize)]
pub struct MediatorAccountList {
    pub accounts: Vec<Account>,
    pub cursor: u32,
}

impl Mediator {
    /// Fetch an account information from the mediator
    /// - `atm` - The ATM client to use
    /// - `profile` - The profile to use
    /// - `did_hash` - The DID hash to fetch (Defaults to the profile DID hash if not provided)
    pub async fn account_get(
        &self,
        atm: &ATM,
        profile: &Arc<Profile>,
        did_hash: Option<String>,
    ) -> Result<Option<Account>, ATMError> {
        let _span = span!(Level::DEBUG, "account_get");

        async move {
            let did_hash = did_hash.unwrap_or_else(|| digest(&profile.inner.did));
            debug!("Requesting account ({}) from mediator.", did_hash);

            let (profile_did, mediator_did) = profile.dids()?;

            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let msg = Message::build(
                Uuid::new_v4().into(),
                "https://didcomm.org/mediator/1.0/account-management".to_owned(),
                json!({"AccountGet":  did_hash}),
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

            // send the message
            if let SendMessageResponse::Message(message) =
                atm.send_message(profile, &msg, &msg_id, true, true).await?
            {
                self._parse_account_get_response(&message)
            } else {
                Err(ATMError::MsgReceiveError(
                    "No response from mediator".to_owned(),
                ))
            }
        }
        .instrument(_span)
        .await
    }

    /// Parses the response from the mediator for account_get
    fn _parse_account_get_response(&self, message: &Message) -> Result<Option<Account>, ATMError> {
        serde_json::from_value(message.body.clone()).map_err(|err| {
            ATMError::MsgReceiveError(format!(
                "Mediator Account Get response could not be parsed. Reason: {}",
                err
            ))
        })
    }

    /// Create a new account on the Mediator for a given DID
    /// - `atm` - The ATM client to use
    /// - `profile` - The profile to use
    /// - `did_hash` - The DID hash to create
    /// - `acls` - The ACLs to set for the account (Defaults to None if not provided)
    ///                  - NOTE: If not an admin account, the mediator will default this to the default ACL
    ///
    /// NOTE: If the mediator is running in explicit_allow mode, then only admin level accounts can add new accounts
    /// # Returns
    /// The account created on the mediator, or the existing account if it already exists
    pub async fn account_add(
        &self,
        atm: &ATM,
        profile: &Arc<Profile>,
        did_hash: &str,
        acls: Option<MediatorACLSet>,
    ) -> Result<Account, ATMError> {
        let _span = span!(Level::DEBUG, "account_add");

        async move {
            debug!("Adding account ({}) to mediator.", did_hash);

            let (profile_did, mediator_did) = profile.dids()?;

            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let msg = Message::build(
                Uuid::new_v4().into(),
                "https://didcomm.org/mediator/1.0/account-management".to_owned(),
                json!({"AccountAdd": {"did_hash": did_hash, "acls": acls.map(|a| a.to_u64())}}),
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
                self._parse_account_add_response(&message)
            } else {
                Err(ATMError::MsgReceiveError(
                    "No response from mediator".to_owned(),
                ))
            }
        }
        .instrument(_span)
        .await
    }

    /// Parses the response from the mediator for account_add
    fn _parse_account_add_response(&self, message: &Message) -> Result<Account, ATMError> {
        serde_json::from_value(message.body.clone()).map_err(|err| {
            ATMError::MsgReceiveError(format!(
                "Mediator Account Add response could not be parsed. Reason: {}",
                err
            ))
        })
    }

    /// Removes an account from the mediator
    /// - `atm` - The ATM client to use
    /// - `profile` - The profile to use
    /// - `did_hash` - The DID hash to remove (Defaults to the profile DID hash if not provided)
    pub async fn account_remove(
        &self,
        atm: &ATM,
        profile: &Arc<Profile>,
        did_hash: Option<String>,
    ) -> Result<bool, ATMError> {
        let _span = span!(Level::DEBUG, "account_remove");

        async move {
            let did_hash = did_hash.unwrap_or_else(|| digest(&profile.inner.did));
            debug!("Removing account ({}) from mediator.", did_hash);

            let (profile_did, mediator_did) = profile.dids()?;

            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let msg = Message::build(
                Uuid::new_v4().into(),
                "https://didcomm.org/mediator/1.0/account-management".to_owned(),
                json!({"AccountRemove":  did_hash}),
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
                self._parse_account_remove_response(&message)
            } else {
                Err(ATMError::MsgReceiveError(
                    "No response from mediator".to_owned(),
                ))
            }
        }
        .instrument(_span)
        .await
    }

    /// Parses the response from the mediator for account_remove
    fn _parse_account_remove_response(&self, message: &Message) -> Result<bool, ATMError> {
        serde_json::from_value(message.body.clone()).map_err(|err| {
            ATMError::MsgReceiveError(format!(
                "Mediator Account Remove response could not be parsed. Reason: {}",
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
    /// NOTE: `limit` may return more than `limit`
    pub async fn accounts_list(
        &self,
        atm: &ATM,
        profile: &Arc<Profile>,
        cursor: Option<u32>,
        limit: Option<u32>,
    ) -> Result<MediatorAccountList, ATMError> {
        let _span = span!(Level::DEBUG, "accounts_list");

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
                "https://didcomm.org/mediator/1.0/account-management".to_owned(),
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
                .send_message(profile, &msg, &msg_id, true, true)
                .await? {
                self._parse_accounts_list_response(&message)
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
    fn _parse_accounts_list_response(
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
}
