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
