/*!
 * This module contains functions to check various ACLs for a given DID.
 * At all times it works on a SHA256 hash of the DID.
 *
 */

use super::errors::MediatorError;
use crate::{database::session::Session, SharedData};
use affinidi_messaging_sdk::protocols::mediator::acls::ACLMode;
use tracing::debug;

/// Pre-authenticated ACL check to see if DID is blocked from connecting to the mediator
/// - `shared`: Mediator Shared State
/// - `did_hash`: SHA256 hash of the DID we are looking up
/// - `session`: Optional: If provided uses ACL's in Session, otherwise looks up from database
///
/// Returns true if the DID is allowed to connect, false otherwise
pub async fn acl_authentication_check(
    shared: &SharedData,
    did_hash: &str,
    session: Option<&Session>,
) -> Result<bool, MediatorError> {
    // Do we know about this DID?
    let acls = if let Some(session) = session {
        session.global_acls
    } else {
        debug!("Fetching global_acls from database did_hash({})", did_hash);
        let acls = shared
            .database
            .get_global_acls(
                &[did_hash.to_string()],
                shared.config.security.acl_mode.clone(),
            )
            .await?;
        if let Some(acl) = acls.acl_response.first() {
            debug!(
                "Fetched global_acl({:x}) from database for did_hash({})",
                acl.acls.into_bits(),
                did_hash
            );
            acl.acls
        } else {
            debug!(
                "No global_acl set for did_hash({})! Using default_acl...",
                did_hash
            );
            shared.config.security.default_acl
        }
    };

    if shared.config.security.acl_mode == ACLMode::ExplicitDeny {
        Ok(!acls.blocked())
    } else {
        Ok(acls.blocked())
    }
}
