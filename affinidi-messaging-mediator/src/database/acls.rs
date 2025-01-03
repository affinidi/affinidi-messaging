use affinidi_messaging_sdk::protocols::mediator::{
    global_acls::{GlobalACLConfig, GlobalACLMode, GlobalACLSet, MediatorGlobalACLResponse},
    local_acls::{LocalACLMode, LocalACLSet},
};
use redis::{from_redis_value, Cmd, Pipeline, Value};
use tracing::{debug, span, Instrument, Level};

use crate::common::errors::MediatorError;

use super::DatabaseHandler;

impl DatabaseHandler {
    /// Retrieves a list of global ACLs for given DIDS
    /// - `dids` - List of DIDs (hashes) to retrieve ACLs for (limit 100)
    /// - Returns a list of ACLs for the given DIDs
    pub(crate) async fn global_acls_get(
        &self,
        dids: &[String],
        mediator_acl_mode: GlobalACLMode,
    ) -> Result<MediatorGlobalACLResponse, MediatorError> {
        let _span = span!(Level::DEBUG, "global_acls_get");

        async move {
            debug!(
                "Requesting global ACLs for ({}) DIDs from mediator",
                dids.len()
            );
            if dids.len() > 100 {
                return Err(MediatorError::DatabaseError(
                    "NA".to_string(),
                    "# of DIDs cannot exceed 100".to_string(),
                ));
            }

            let mut con = self.get_async_connection().await?;

            let mut query = Pipeline::new();

            for did in dids {
                query.add_command(Cmd::hget(format!("DID:{}", did), "GLOBAL_ACL"));
            }

            let result: Vec<Value> = query.query_async(&mut con).await.map_err(|err| {
                MediatorError::DatabaseError(
                    "NA".to_string(),
                    format!("global_acls_get failed. Reason: {}", err),
                )
            })?;

            let mut acl_response: MediatorGlobalACLResponse = MediatorGlobalACLResponse {
                acl_response: vec![],
                mediator_acl_mode,
            };
            for (index, item) in result.iter().enumerate() {
                if let Ok(acls) = from_redis_value(item) {
                    acl_response.acl_response.push(GlobalACLConfig {
                        did_hash: dids[index].clone(),
                        acl_value: acls,
                        acls: GlobalACLSet::from_bits(acls),
                    });
                }
            }
            Ok(acl_response)
        }
        .instrument(_span)
        .await
    }

    /// Checks if the `value_hash` exists in the local ACL for the given `key_hash`
    /// - `key_hash` - Hash of the DID we are checking against (typically the TO address)
    /// - `value_hash` - Hash of the DID we are checking for (typically the FROM address)
    ///
    /// Returns true if it exists, false otherwise
    pub async fn local_acl_lookup(
        &self,
        to_hash: &str,
        from_hash: Option<String>,
    ) -> Result<bool, MediatorError> {
        let mut con = self.get_async_connection().await?;

        if let Some(from_hash) = &from_hash {
            let (exists, local_acl): (bool, Option<u16>) = deadpool_redis::redis::pipe()
                .atomic()
                .cmd("SISMEMBER")
                .arg(["LOCAL_ACL:", to_hash].concat())
                .arg(from_hash)
                .cmd("HGET")
                .arg(["DID:", to_hash].concat())
                .arg("LOCAL_ACL")
                .query_async(&mut con)
                .await
                .map_err(|err| {
                    MediatorError::DatabaseError(
                        "NA".to_string(),
                        format!("get_global_acls failed. Reason: {}", err),
                    )
                })?;

            let local_acl = if let Some(local_acl) = local_acl {
                LocalACLSet::from_bits(local_acl)
            } else {
                debug!("Local ACL not found for DID: {}", to_hash);
                return Ok(false);
            };

            if local_acl.acl_mode() == LocalACLMode::ExplicitAllow {
                debug!(
                    "local_acl_lookup == true for to_hash({}), from_hash({})",
                    to_hash, from_hash
                );
                Ok(exists)
            } else {
                debug!(
                    "local_acl_lookup == false for to_hash({}), from_hash({})",
                    to_hash, from_hash
                );
                Ok(!exists)
            }
        } else {
            // Anonymous Message
            Ok(self.local_acl_get(to_hash).await?.anon_allowed())
        }
    }

    pub async fn local_acl_get(&self, did_hash: &str) -> Result<LocalACLSet, MediatorError> {
        let mut con = self.get_async_connection().await?;

        let local_acl: Option<u16> = deadpool_redis::redis::cmd("HGET")
            .arg(["DID:", did_hash].concat())
            .arg("LOCAL_ACL")
            .query_async(&mut con)
            .await
            .map_err(|err| {
                MediatorError::DatabaseError(
                    "NA".to_string(),
                    format!("get_global_acls failed. Reason: {}", err),
                )
            })?;

        if let Some(local_acl) = local_acl {
            Ok(LocalACLSet::from_bits(local_acl))
        } else {
            debug!("Local ACL not found for DID: {}", did_hash);
            Err(MediatorError::PermissionError(
                "NA".into(),
                "Local ACL non existent".into(),
            ))
        }
    }
}
