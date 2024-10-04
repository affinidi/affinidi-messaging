use affinidi_messaging_sdk::protocols::mediator::MediatorAdminList;
use redis::{from_redis_value, Value};
use tracing::{debug, info, span, Instrument, Level};

use crate::common::errors::MediatorError;

use super::DatabaseHandler;

impl DatabaseHandler {
    /// Ensures that the mediator admin account is correctly configured and set up.
    /// It does not do any cleanup or maintenance of other admin accounts.
    /// Updates both the DID role type and the global ADMIN Set in Redis.
    pub(crate) async fn setup_admin_account(&self, admin_did: &str) -> Result<(), MediatorError> {
        let mut con = self.get_async_connection().await?;

        let did_hash = sha256::digest(admin_did);
        debug!("Admin DID ({}) == hash ({})", admin_did, did_hash);

        deadpool_redis::redis::pipe()
            .atomic()
            .cmd("SADD")
            .arg("ADMINS")
            .arg(&did_hash)
            .ignore()
            .cmd("HSET")
            .arg(["DID:", &did_hash].concat())
            .arg("ADMIN")
            .arg(1)
            .ignore()
            .query_async(&mut con)
            .await
            .map_err(|err| {
                MediatorError::DatabaseError(
                    "NA".to_string(),
                    format!(
                        "error in setup of admin account for ({}). Reason: {}",
                        admin_did, err
                    ),
                )
            })?;

        info!("Admin account successfully setup: {}", admin_did);
        Ok(())
    }

    pub(crate) async fn check_admin_account(&self, did_hash: &str) -> Result<bool, MediatorError> {
        let mut con = self.get_async_connection().await?;

        let result: Vec<i32> = deadpool_redis::redis::pipe()
            .atomic()
            .cmd("SISMEMBER")
            .arg("ADMINS")
            .arg(did_hash)
            .cmd("HGET")
            .arg(["DID:", did_hash].concat())
            .arg("ADMIN")
            .query_async(&mut con)
            .await
            .map_err(|err| {
                MediatorError::DatabaseError(
                    "NA".to_string(),
                    format!(
                        "error in check of admin account for ({}). Reason: {}",
                        did_hash, err
                    ),
                )
            })?;

        if result.iter().sum::<i32>() == 2 {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Retrieves up to 100 admin accounts from the mediator
    /// - `cursor` - The offset to start from (0 is the start)
    /// - `limit` - The maximum number of accounts to return
    pub(crate) async fn list_admin_accounts(
        &self,
        cursor: u32,
        limit: u32,
    ) -> Result<MediatorAdminList, MediatorError> {
        let _span = span!(
            Level::DEBUG,
            "list_admin_accounts",
            cursor = cursor,
            limit = limit
        );

        async move {
            debug!("Requesting list of Admin accounts from mediator");
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
                .arg("ADMINS")
                .arg(cursor)
                .arg("COUNT")
                .arg(100)
                .query_async(&mut con)
                .await
                .map_err(|err| {
                    MediatorError::DatabaseError(
                        "NA".to_string(),
                        format!("SSCAN cursor ({}) failed. Reason: {}", cursor, err),
                    )
                })?;

            let mut new_cursor: u32 = 0;
            let mut admins: Vec<String> = vec![];
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

                admins = from_redis_value(value.last().unwrap()).map_err(|err| {
                    MediatorError::DatabaseError(
                        "NA".to_string(),
                        format!("admin list could not be correctly parsed. Reason: {}", err),
                    )
                })?;
            }
            Ok(MediatorAdminList {
                admins,
                cursor: new_cursor,
            })
        }
        .instrument(_span)
        .await
    }
}
