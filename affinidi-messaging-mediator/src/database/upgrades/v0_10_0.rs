/*!
 * Upgrades to version 0.10.0
 *
 * Adds ACL Flag to set queue limits. Sets this flag based on the mediator configuration
 */
use crate::database::Database;
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_sdk::protocols::mediator::acls::MediatorACLSet;
use tracing::info;

impl Database {
    /// No schema changes, simply update version number
    pub(crate) async fn upgrade_0_10_0(
        &self,
        default_acl: &MediatorACLSet,
    ) -> Result<(), MediatorError> {
        if default_acl.get_self_manage_queue_limit() {
            // Set the self_change_queue_limit flag to true for all accounts
            info!("Setting self_change_queue_limit flag to true for all accounts");
            self.update_acl_flag_queue_limit().await?;
        } else {
            // ACL flag is not enabled by default, so do NOT add this to existing DID ACLs
        }

        self.upgrade_change_schema_version("0.10.0").await
    }

    async fn update_acl_flag_queue_limit(&self) -> Result<(), MediatorError> {
        // Update all accounts to have the self_change_queue_limit flag set to true
        let mut cursor: u32 = 0;
        let mut counter = 0;
        loop {
            let dids = self.account_list(cursor, 100).await?;

            for account in dids.accounts {
                counter += 1;

                let mut acls = MediatorACLSet::from_u64(account.acls);
                acls.set_self_manage_queue_limit(true);
                self.set_did_acl(&account.did_hash, &acls).await?;
            }

            if dids.cursor == 0 {
                break;
            } else {
                cursor = dids.cursor;
            }
        }
        info!(
            "Updated {} accounts with self_change_queue_limit flag",
            counter
        );
        Ok(())
    }
}
