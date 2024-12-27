use affinidi_messaging_sdk::protocols::mediator::acls::{
    ACLConfig, ACLMode, GlobalACLSet, MediatorGlobalACLResponse,
};
use redis::{from_redis_value, Cmd, Pipeline, Value};
use tracing::{debug, span, Instrument, Level};

use crate::common::errors::MediatorError;

use super::DatabaseHandler;

impl DatabaseHandler {
    /// Retrieves a list of global ACLs for given DIDS
    /// - `dids` - List of DIDs (hashes) to retrieve ACLs for (limit 100)
    /// - Returns a list of ACLs for the given DIDs
    pub(crate) async fn get_global_acls(
        &self,
        dids: &Vec<String>,
        mediator_acl_mode: ACLMode,
    ) -> Result<MediatorGlobalACLResponse, MediatorError> {
        let _span = span!(Level::DEBUG, "get_global_acls");

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
                    format!("get_global_acls failed. Reason: {}", err),
                )
            })?;

            let mut acl_response: MediatorGlobalACLResponse = MediatorGlobalACLResponse {
                acl_response: vec![],
                mediator_acl_mode,
            };
            for (index, item) in result.iter().enumerate() {
                if let Ok(acls) = from_redis_value(item) {
                    acl_response.acl_response.push(ACLConfig {
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
}
