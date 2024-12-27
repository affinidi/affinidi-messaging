//! All Redis related database methods are handled by `DatabaseHandler` module

pub mod accounts;
pub(crate) mod acls;
pub mod admin_accounts;
pub mod delete;
pub mod fetch;
pub mod get;
pub mod handlers;
pub mod list;
pub(crate) mod oob_discovery;
pub mod session;
pub mod stats;
pub mod store;
pub mod streaming;
#[derive(Clone)]
pub struct DatabaseHandler {
    pub pool: deadpool_redis::Pool,
    redis_url: String,
}
