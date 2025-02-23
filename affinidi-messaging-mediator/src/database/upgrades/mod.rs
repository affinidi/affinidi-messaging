/*!
 * Handles upgrades from one version to another for the database schema
 */

use super::Database;
use affinidi_messaging_mediator_common::errors::MediatorError;

impl Database {
    pub(crate) async fn upgrade_change_schema_version(
        &self,
        version: &str,
    ) -> Result<(), MediatorError> {
        let mut con = self.0.get_async_connection().await?;
        deadpool_redis::redis::Cmd::hset("GLOBAL", "SCHEMA_VERSION", version)
            .exec_async(&mut con)
            .await
            .map_err(|e| {
                MediatorError::DatabaseError(
                    "NA".into(),
                    format!("Couldn't set database SCHEMA_VERSION: {}", e),
                )
            })
    }

    /// No schema changes, simply update version number
    pub(crate) async fn upgrade_0_10_0(&self) -> Result<(), MediatorError> {
        self.upgrade_change_schema_version("0.10.0").await
    }
}
