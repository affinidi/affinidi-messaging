/*!
 * This module contains functions to check various ACLs for a given DID.
 * At all times it works on a SHA256 hash of the DID.
 *
 */

use super::errors::MediatorError;
use crate::SharedData;
use affinidi_messaging_sdk::protocols::mediator::acls::ACLMode;
use tracing::debug;

/// Pre-authenticated ACL check to see if DID is blocked from connecting to the mediator
/// Returns true if the DID is allowed to connect, false otherwise
pub async fn acl_authentication_check(
    shared: &SharedData,
    did_hash: &str,
) -> Result<bool, MediatorError> {
    // Do we know about this DID?
    let acls = shared
        .database
        .get_global_acls(
            &[did_hash.to_string()],
            shared.config.security.acl_mode.clone(),
        )
        .await?;
    if let Some(acl) = acls.acl_response.first() {
        debug!("DID found in database, using ACL");
        if shared.config.security.acl_mode == ACLMode::ExplicitDeny {
            Ok(!acl.acls.blocked())
        } else {
            Ok(acl.acls.blocked())
        }
    } else {
        debug!("DID not found in database, using default ACL");
        if shared.config.security.acl_mode == ACLMode::ExplicitDeny {
            Ok(!shared.config.security.default_acl.blocked())
        } else {
            Ok(shared.config.security.default_acl.blocked())
        }
    }
}
