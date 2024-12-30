/*!
 * This module contains functions to check various ACLs for a given DID.
 * At all times it works on a SHA256 hash of the DID.
 *
 */

use super::errors::MediatorError;
use crate::{database::session::Session, SharedData};
use affinidi_messaging_sdk::protocols::mediator::acls::{ACLMode, GlobalACLSet};
use tracing::debug;

pub(crate) trait ACLCheck {
    async fn authentication_check(
        shared: &SharedData,
        did_hash: &str,
        session: Option<&Session>,
    ) -> Result<bool, MediatorError>;
    fn check_blocked(&self, mediator_mode: &ACLMode) -> bool;
    fn check_local(&self, mediator_mode: &ACLMode) -> bool;
    fn check_inbound(&self, mediator_mode: &ACLMode) -> bool;
    fn check_invites(&self, mediator_mode: &ACLMode) -> bool;
    fn check_forward_from(&self, mediator_mode: &ACLMode) -> bool;
    fn check_forward_to(&self, mediator_mode: &ACLMode) -> bool;
}

impl ACLCheck for GlobalACLSet {
    /// Pre-authenticated ACL check to see if DID is blocked from connecting to the mediator
    /// - `shared`: Mediator Shared State
    /// - `did_hash`: SHA256 hash of the DID we are looking up
    /// - `session`: Optional: If provided uses ACL's in Session, otherwise looks up from database
    ///
    /// Returns true if the DID is allowed to connect, false otherwise
    async fn authentication_check(
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

        Ok(acls.check_blocked(&shared.config.security.acl_mode))
    }

    /// Check if session is blocked
    /// returns true if allowed
    /// returns false if blocked
    fn check_blocked(&self, mediator_mode: &ACLMode) -> bool {
        if mediator_mode == &ACLMode::ExplicitDeny {
            !self.blocked()
        } else {
            self.blocked()
        }
    }

    /// Check if session is allowed locally
    /// returns true if allowed
    /// returns false if blocked
    fn check_local(&self, mediator_mode: &ACLMode) -> bool {
        if mediator_mode == &ACLMode::ExplicitDeny {
            !self.local()
        } else {
            self.local()
        }
    }

    /// Is the DID allowed to send messages to/through the mediator?
    /// returns true if allowed
    /// returns false if blocked
    fn check_inbound(&self, mediator_mode: &ACLMode) -> bool {
        if mediator_mode == &ACLMode::ExplicitDeny {
            !self.inbound()
        } else {
            self.inbound()
        }
    }

    /// Is the DID allowed to create/delete OOB Invitations?
    /// returns true if allowed
    /// returns false if blocked
    fn check_invites(&self, mediator_mode: &ACLMode) -> bool {
        if mediator_mode == &ACLMode::ExplicitDeny {
            !self.create_invites()
        } else {
            self.create_invites()
        }
    }

    /// Is the DID allowed to forward to other DIDs?
    /// returns true if allowed
    /// returns false if blocked
    fn check_forward_from(&self, mediator_mode: &ACLMode) -> bool {
        if mediator_mode == &ACLMode::ExplicitDeny {
            !self.forward_from()
        } else {
            self.forward_from()
        }
    }

    /// Is the DID allowed to receive messages from other DIDs?
    /// returns true if allowed
    /// returns false if blocked
    fn check_forward_to(&self, mediator_mode: &ACLMode) -> bool {
        if mediator_mode == &ACLMode::ExplicitDeny {
            !self.forward_to()
        } else {
            self.forward_to()
        }
    }
}
