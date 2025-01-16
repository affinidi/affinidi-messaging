use affinidi_messaging_sdk::protocols::mediator::{
    acls::{ACLModeType, MediatorACLSet},
    acls_handler::{MediatorACLExpanded, MediatorACLResponse},
};
use redis::{from_redis_value, Cmd, Pipeline, Value};
use tracing::{debug, span, Instrument, Level};

use crate::common::errors::MediatorError;

use super::DatabaseHandler;

impl DatabaseHandler {
    /// Replace the ACL for a given DID
    pub(crate) async fn set_did_acl(
        &self,
        did_hash: &str,
        acls: &MediatorACLSet,
    ) -> Result<(), MediatorError> {
        let _span = span!(Level::DEBUG, "set_acl");

        async move {
            debug!("Setting ACL for ({}) DID in mediator", did_hash);

            let mut con = self.get_async_connection().await?;

            deadpool_redis::redis::Cmd::hset(
                format!("DID:{}", did_hash),
                "ACLS",
                acls.to_hex_string(),
            )
            .exec_async(&mut con)
            .await
            .map_err(|err| {
                MediatorError::DatabaseError(
                    "NA".to_string(),
                    format!("set_acl failed. Reason: {}", err),
                )
            })?;

            Ok(())
        }
        .instrument(_span)
        .await
    }

    /// Get ACL for a given DID
    /// Returns the ACL for the given DID, or None if DID isn't found
    pub(crate) async fn get_did_acl(
        &self,
        did_hash: &str,
    ) -> Result<Option<MediatorACLSet>, MediatorError> {
        let _span = span!(Level::DEBUG, "get_did_acl");

        async move {
            debug!("Requesting ACL for ({}) DID from mediator", did_hash);

            let mut con = self.get_async_connection().await?;

            let acl: Option<String> =
                deadpool_redis::redis::Cmd::hget(format!("DID:{}", did_hash), "ACLS")
                    .query_async(&mut con)
                    .await
                    .map_err(|err| {
                        MediatorError::DatabaseError(
                            "NA".to_string(),
                            format!("get_did_acls failed. Reason: {}", err),
                        )
                    })?;

            if let Some(acl) = acl {
                Ok(Some(MediatorACLSet::from_hex_string(&acl).map_err(
                    |e| MediatorError::InternalError(did_hash.into(), e.to_string()),
                )?))
            } else {
                Ok(None)
            }
        }
        .instrument(_span)
        .await
    }

    /// Retrieves a list of ACLs for given DIDS
    /// - `dids` - List of DIDs (hashes) to retrieve ACLs for (limit 100)
    /// - Returns a list of ACLs for the given DIDs
    pub(crate) async fn get_did_acls(
        &self,
        dids: &[String],
        mediator_acl_mode: ACLModeType,
    ) -> Result<MediatorACLResponse, MediatorError> {
        let _span = span!(Level::DEBUG, "get_did_acls");

        async move {
            debug!("Requesting ACLs for ({}) DIDs from mediator", dids.len());
            if dids.len() > 100 {
                return Err(MediatorError::DatabaseError(
                    "NA".to_string(),
                    "# of DIDs cannot exceed 100".to_string(),
                ));
            }

            let mut con = self.get_async_connection().await?;

            let mut query = Pipeline::new();
            query.atomic();

            for did in dids {
                query.add_command(Cmd::hget(format!("DID:{}", did), "ACLS"));
            }

            let result: Vec<Value> = query.query_async(&mut con).await.map_err(|err| {
                MediatorError::DatabaseError(
                    "NA".to_string(),
                    format!("get_did_acls failed. Reason: {}", err),
                )
            })?;

            let mut acl_response: MediatorACLResponse = MediatorACLResponse {
                acl_response: vec![],
                mediator_acl_mode,
            };
            for (index, item) in result.iter().enumerate() {
                if let Ok(acls_hex) = from_redis_value::<String>(item) {
                    let acls = MediatorACLSet::from_hex_string(&acls_hex).map_err(|e| {
                        MediatorError::InternalError(dids[index].clone(), e.to_string())
                    })?;
                    acl_response.acl_response.push(MediatorACLExpanded {
                        did_hash: dids[index].clone(),
                        acl_value: acls.to_hex_string(),
                        acls,
                    });
                }
            }
            Ok(acl_response)
        }
        .instrument(_span)
        .await
    }

    /// Checks if the `to_hash` is allowed in the local ACL for the given `key_hash`
    /// - `to_hash` - Hash of the DID we are checking against (typically the TO address)
    /// - `from_hash` - Hash of the DID we are checking for (typically the FROM address)
    ///
    /// Returns true if it exists, false otherwise
    pub async fn local_acl_allowed(
        &self,
        to_hash: &str,
        from_hash: Option<String>,
    ) -> Result<bool, MediatorError> {
        let mut con = self.get_async_connection().await?;

        if let Some(from_hash) = &from_hash {
            let (exists, acl): (bool, Option<String>) = deadpool_redis::redis::pipe()
                .atomic()
                .cmd("SISMEMBER")
                .arg(["LOCAL_ACL:", to_hash].concat())
                .arg(from_hash)
                .cmd("HGET")
                .arg(["DID:", to_hash].concat())
                .arg("ACLS")
                .query_async(&mut con)
                .await
                .map_err(|err| {
                    MediatorError::DatabaseError(
                        "NA".to_string(),
                        format!("get_global_acls failed. Reason: {}", err),
                    )
                })?;

            let acl = if let Some(acl) = acl {
                MediatorACLSet::from_hex_string(&acl)
                    .map_err(|e| MediatorError::InternalError(to_hash.into(), e.to_string()))?
            } else {
                debug!("ACL not found for DID: {}", to_hash);
                return Ok(false);
            };

            if acl.get_did_acl_mode().0 == ACLModeType::ExplicitAllow {
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
            if let Some(acl) = self.get_did_acl(to_hash).await? {
                Ok(acl.get_anon_receive().0)
            } else {
                Ok(false)
            }
        }
    }
}
