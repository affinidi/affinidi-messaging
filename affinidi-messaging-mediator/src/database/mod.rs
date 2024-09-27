//! All Redis related database methods are handled by `DatabaseHandler` module
use crate::common::errors::MediatorError;
use tracing::{debug, info};

pub mod delete;
pub mod fetch;
pub mod get;
pub mod handlers;
pub mod list;
pub mod session;
pub mod stats;
pub mod store;
pub mod streaming;
#[derive(Clone)]
pub struct DatabaseHandler {
    pub pool: deadpool_redis::Pool,
    redis_url: String,
}

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
            .cmd("HSET")
            .arg(["DID:", &did_hash].concat())
            .arg("ADMIN")
            .arg(1)
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

        info!("Admin account successfully setup");
        Ok(())
    }
}
