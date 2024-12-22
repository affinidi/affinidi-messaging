//! Handles scanning, adding and removing DID accounts from the mediator
use affinidi_messaging_sdk::protocols::mediator::MediatorAccountList;
use redis::{from_redis_value, Value};
use tracing::{debug, span, Instrument, Level};

use crate::common::errors::MediatorError;

use super::DatabaseHandler;

impl DatabaseHandler {
    /// Add a DID account to the mediator
    /// - `did_hash` - SHA256 hash of the DID
    pub(crate) async fn add_account(&self, did_hash: &str) -> Result<bool, MediatorError> {
        let _span = span!(Level::DEBUG, "add_account", "did_hash" = did_hash,);

        async move {
            debug!("Adding account to the mediator");

            let mut con = self.get_async_connection().await?;

            let result: i32 = deadpool_redis::redis::pipe()
                .atomic()
                .cmd("SADD")
                .arg("KNOWN_DIDS")
                .arg(did_hash)
                .query_async(&mut con)
                .await
                .map_err(|err| {
                    MediatorError::DatabaseError(
                        "NA".to_string(),
                        format!("Add failed. Reason: {}", err),
                    )
                })?;
            debug!("Account added successfully: {:?}", result);

            Ok(true)
        }
        .instrument(_span)
        .await
    }

    /// Removes an account from the mediator
    /// - `did_hash` - SHA256 Hash of DID to remove
    pub(crate) async fn remove_account(&self, did_hash: &str) -> Result<i32, MediatorError> {
        let _span = span!(Level::DEBUG, "remove_account", "did_hash" = did_hash,);

        async move {
            debug!("Removing account from the mediator");

            /*
            let mut con = self.get_async_connection().await?;

            let result = deadpool_redis::redis::pipe()
                .atomic()
                .cmd("SREM")
                .arg("KNOWN_DIDS");

            // Remove from the ADMINS Set
            for account in &accounts {
                debug!("Removing Admin account: {}", account);
                tx = tx.arg(account);
            }

            // Remove admin field on each DID
            for account in &accounts {
                tx = tx.cmd("HDEL").arg(account).arg("ROLE_TYPE");
            }

            let result: Vec<i32> = tx.query_async(&mut con).await.map_err(|err| {
                MediatorError::DatabaseError(
                    "NA".to_string(),
                    format!("Remove failed. Reason: {}", err),
                )
            })?;
            debug!("Admin accounts removed successfully: {:?}", result);

            Ok(result.first().unwrap_or(&0).to_owned())
            */
            Ok(0)
        }
        .instrument(_span)
        .await
    }

    /// Retrieves up to 100 accounts from the mediator
    /// - `cursor` - The offset to start from (0 is the start)
    /// - `limit` - The maximum number of accounts to return (max 100)
    /// NOTE: `limit` may return more than what is specified. This is a peculiarity of Redis
    pub(crate) async fn list_accounts(
        &self,
        cursor: u32,
        limit: u32,
    ) -> Result<MediatorAccountList, MediatorError> {
        let _span = span!(
            Level::DEBUG,
            "list_accounts",
            cursor = cursor,
            limit = limit
        );

        async move {
            debug!("Requesting list of accounts from mediator");
            if limit > 100 {
                return Err(MediatorError::DatabaseError(
                    "NA".to_string(),
                    "limit cannot exceed 100".to_string(),
                ));
            }

            let mut con = self.get_async_connection().await?;

            let result: Vec<Value> = deadpool_redis::redis::pipe()
                .atomic()
                .cmd("SSCAN")
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

            let mut new_cursor: u32 = 0;
            let mut accounts: Vec<String> = vec![];
            for item in &result {
                let value: Vec<Value> = from_redis_value(item).unwrap();
                if value.len() != 2 {
                    return Err(MediatorError::DatabaseError(
                        "NA".to_string(),
                        "SSCAN result is not a tuple".to_string(),
                    ));
                }
                new_cursor = from_redis_value::<String>(value.first().unwrap())
                    .map_err(|err| {
                        MediatorError::DatabaseError(
                            "NA".into(),
                            format!("cursor could not be correctly parsed. Reason: {}", err),
                        )
                    })?
                    .parse::<u32>()
                    .unwrap();

                accounts = from_redis_value(value.last().unwrap()).map_err(|err| {
                    MediatorError::DatabaseError(
                        "NA".to_string(),
                        format!(
                            "account list could not be correctly parsed. Reason: {}",
                            err
                        ),
                    )
                })?;
            }
            Ok(MediatorAccountList {
                accounts,
                cursor: new_cursor,
            })
        }
        .instrument(_span)
        .await
    }
}
