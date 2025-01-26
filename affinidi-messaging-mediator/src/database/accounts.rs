//! Handles scanning, adding and removing DID accounts from the mediator
use std::collections::HashMap;

use super::{session::Session, DatabaseHandler};
use crate::common::errors::MediatorError;
use affinidi_messaging_sdk::{
    messages::Folder,
    protocols::mediator::{
        accounts::{Account, AccountType, MediatorAccountList},
        acls::MediatorACLSet,
    },
};
use redis::Pipeline;
use tracing::{debug, span, warn, Instrument, Level};

impl DatabaseHandler {
    /// Quick and efficient check if an account exists locally in the mediator
    pub(crate) async fn account_exists(&self, did_hash: &str) -> Result<bool, MediatorError> {
        let mut con = self.get_async_connection().await?;

        deadpool_redis::redis::cmd("EXISTS")
            .arg(["DID:", did_hash].concat())
            .query_async(&mut con)
            .await
            .map_err(|err| {
                MediatorError::DatabaseError(
                    "NA".to_string(),
                    format!("Add failed. Reason: {}", err),
                )
            })
    }

    /// Grab Account information
    pub(crate) async fn account_get(
        &self,
        did_hash: &str,
    ) -> Result<Option<Account>, MediatorError> {
        let mut con = self.get_async_connection().await?;

        let response: HashMap<String, String> = deadpool_redis::redis::cmd("HGETALL")
            .arg(["DID:", did_hash].concat())
            .query_async(&mut con)
            .await
            .map_err(|err| {
                MediatorError::DatabaseError(
                    "NA".to_string(),
                    format!("Add failed. Reason: {}", err),
                )
            })?;

        if response.is_empty() {
            debug!("Account {} does not exist", did_hash);
            return Ok(None);
        }

        let _type = if let Some(_type) = response.get("ROLE_TYPE") {
            AccountType::from(_type.as_str())
        } else {
            warn!("Account {} does not have a role type", did_hash);
            return Err(MediatorError::InternalError(
                "NA".to_string(),
                "DID is missing a role_type".to_string(),
            ));
        };

        let acls = if let Some(acls) = response.get("ACLS") {
            u64::from_str_radix(acls, 16).unwrap_or(0_u64)
        } else {
            warn!("Account {} does not have ACLs", did_hash);
            return Err(MediatorError::InternalError(
                "NA".to_string(),
                "DID is missing ACLs".to_string(),
            ));
        };

        Ok(Some(Account {
            did_hash: did_hash.to_string(),
            _type,
            acls,
        }))
    }

    /// Add a DID account to the mediator
    /// - `did_hash` - SHA256 hash of the DID
    pub(crate) async fn account_add(
        &self,
        did_hash: &str,
        acls: &MediatorACLSet,
    ) -> Result<Account, MediatorError> {
        let _span = span!(Level::DEBUG, "add_account", "did_hash" = did_hash,);

        async move {
            debug!("Adding account to the mediator");

            let mut con = self.get_async_connection().await?;

            deadpool_redis::redis::pipe()
                .atomic()
                .cmd("SADD")
                .arg("KNOWN_DIDS")
                .arg(did_hash)
                .cmd("HSET")
                .arg(["DID:", did_hash].concat())
                .arg("SEND_QUEUE_BYTES")
                .arg(0)
                .arg("SEND_QUEUE_COUNT")
                .arg(0)
                .arg("RECEIVE_QUEUE_BYTES")
                .arg(0)
                .arg("RECEIVE_QUEUE_COUNT")
                .arg(0)
                .arg("ROLE_TYPE")
                .arg::<String>(AccountType::Standard.into())
                .arg("ACLS")
                .arg(acls.to_hex_string())
                .exec_async(&mut con)
                .await
                .map_err(|err| {
                    MediatorError::DatabaseError(
                        "NA".to_string(),
                        format!("account_add() failed. Reason: {}", err),
                    )
                })?;
            debug!("Account added successfully");

            Ok(Account {
                did_hash: did_hash.to_string(),
                _type: AccountType::Standard,
                acls: acls.to_u64(),
            })
        }
        .instrument(_span)
        .await
    }

    /// Removes an account from the mediator
    /// - `did_hash` - SHA256 Hash of DID to remove
    /// - `remove_outbox` - This will remove messages that have not been delivered from this DID to others
    ///                     NOTE: This should only be used as last resort. It is better to let the messages be delivered
    /// - `remove_forwards` - This will remove messages that are queued to be delivered from this DID via forwarding
    pub(crate) async fn account_remove(
        &self,
        session: &Session,
        did_hash: &str,
        remove_outbox: bool,
        remove_forwards: bool,
    ) -> Result<bool, MediatorError> {
        let _span = span!(Level::DEBUG, "account_remove", "did_hash" = did_hash,);

        async move {
            debug!("Removing account from the mediator");

            let current = self.account_get(did_hash).await?;
            debug!("retrieving existing account: {:?}", current);

            if let Some(current) = &current {
                if current._type == AccountType::Mediator {
                    return Err(MediatorError::InternalError(
                        "NA".to_string(),
                        "Cannot remove the mediator account".to_string(),
                    ));
                } else if current._type == AccountType::RootAdmin {
                    return Err(MediatorError::InternalError(
                        "NA".to_string(),
                        "Cannot remove the root admin account".to_string(),
                    ));
                }
            }

            // Step 1 - block access to this account
            let mut blocked_acl = MediatorACLSet::from_u64(0);
            blocked_acl.set_blocked(true);
            self.set_did_acl(did_hash, &blocked_acl).await?;

            // Step 2 - Remove forwarded messages as required
            if remove_forwards {
                // TODO: Implement a way to clear future forward tasks as needed
            }

            // Step 3 - Remove messages from the outbox
            // This will remove any messages that are queued and still to be delivered to other DIDs
            if remove_outbox {
                self.purge_messages(session, did_hash, Folder::Outbox)
                    .await?;
            } else {
                // Just remove the stream key, not the messages in other accounts
                self.delete_folder_stream(session, did_hash, &Folder::Outbox)
                    .await?;
            }

            // Step 4 - Remove messages from the inbox
            // This will remove any messages that are queued and still to be delivered to this DID
            self.purge_messages(session, did_hash, Folder::Inbox)
                .await?;

            // If DID is an admin account then remove from the admin list
            if let Some(current) = current {
                if current._type.is_admin() {
                    self.strip_admin_accounts(vec![did_hash.to_string()])
                        .await?;
                }
            }

            // Remove from Known DIDs
            // Remove DID Record
            let mut con = self.get_async_connection().await?;
            deadpool_redis::redis::pipe()
                .atomic()
                .cmd("SREM")
                .arg("KNOWN_DIDS")
                .arg(did_hash)
                .cmd("DEL")
                .arg(["DID:", did_hash].concat())
                .exec_async(&mut con)
                .await
                .map_err(|err| {
                    MediatorError::DatabaseError(
                        "NA".to_string(),
                        format!("Error removing DID ({}) Records. Reason: {}", did_hash, err),
                    )
                })?;

            Ok(true)
        }
        .instrument(_span)
        .await
    }

    /// Retrieves up to 100 accounts from the mediator
    /// - `cursor` - The offset to start from (0 is the start)
    /// - `limit` - The maximum number of accounts to return (max 100)
    ///    NOTE: `limit` may return more than what is specified. This is a peculiarity of Redis
    pub(crate) async fn account_list(
        &self,
        cursor: u32,
        limit: u32,
    ) -> Result<MediatorAccountList, MediatorError> {
        let _span = span!(Level::DEBUG, "account_list", cursor = cursor, limit = limit);

        async move {
            debug!("Requesting list of accounts from mediator");
            if limit > 100 {
                return Err(MediatorError::DatabaseError(
                    "NA".to_string(),
                    "limit cannot exceed 100".to_string(),
                ));
            }

            let mut con = self.get_async_connection().await?;

            let (new_cursor, dids): (u32, Vec<String>) = deadpool_redis::redis::cmd("SSCAN")
                .arg("KNOWN_DIDS")
                .arg(cursor)
                .arg("COUNT")
                .arg(limit)
                .query_async(&mut con)
                .await
                .map_err(|err| {
                    MediatorError::DatabaseError(
                        "NA".to_string(),
                        format!("SSCAN cursor ({}) failed. Reason: {}", cursor, err),
                    )
                })?;

            // For each DID, fetch their details
            let mut query = Pipeline::new();
            query.atomic();
            for did in &dids {
                query.add_command(redis::Cmd::hget(
                    ["DID:", did].concat(),
                    &["ROLE_TYPE", "ACLS"],
                ));
            }

            let results: Vec<(Option<String>, Option<String>)> =
                query.query_async(&mut con).await.map_err(|err| {
                    MediatorError::DatabaseError(
                        "NA".to_string(),
                        format!("HMGET  failed. Reason: {}", err),
                    )
                })?;

            let mut accounts = Vec::new();
            for (i, (role_type, acls)) in results.iter().enumerate() {
                let _type = if let Some(role_type) = role_type {
                    role_type.as_str().into()
                } else {
                    AccountType::Unknown
                };

                let acls = if let Some(acls) = acls {
                    u64::from_str_radix(acls, 16).unwrap_or(0_u64)
                } else {
                    0_u64
                };

                accounts.push(Account {
                    did_hash: dids[i].clone(),
                    _type,
                    acls,
                });
            }

            Ok(MediatorAccountList {
                accounts,
                cursor: new_cursor,
            })
        }
        .instrument(_span)
        .await
    }

    /// Changes the type of an account to the new type
    /// - `did_hash` - SHA256 hash of the DID
    /// - `_type` - AccountType to change to
    pub(crate) async fn account_change_type(
        &self,
        did_hash: &str,
        _type: &AccountType,
    ) -> Result<(), MediatorError> {
        let _span = span!(
            Level::DEBUG,
            "account_change_type",
            "did_hash" = did_hash,
            "new_type" = _type.to_string()
        );

        async move {
            debug!("Changing account type");

            let mut con = self.get_async_connection().await?;

            deadpool_redis::redis::cmd("HSET")
                .arg(["DID:", did_hash].concat())
                .arg("ROLE_TYPE")
                .arg::<String>(_type.to_owned().into())
                .exec_async(&mut con)
                .await
                .map_err(|err| {
                    MediatorError::DatabaseError(
                        "NA".to_string(),
                        format!("account_change_type() failed. Reason: {}", err),
                    )
                })?;
            debug!("Account type changed successfully");

            Ok(())
        }
        .instrument(_span)
        .await
    }
}
