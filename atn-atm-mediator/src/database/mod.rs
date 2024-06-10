use std::fmt::{self, Display, Formatter};

pub mod delete;
pub mod fetch;
pub mod get;
pub mod handlers;
pub mod list;
pub mod session;
pub mod store;

#[derive(Clone)]
pub struct DatabaseHandler {
    pub pool: deadpool_redis::Pool,
}

/// Statistics for the mediator
#[derive(Default, Debug)]
pub struct MetadataStats {
    pub received_bytes: i64,
    pub sent_bytes: i64,
    pub received_count: i64,
    pub sent_count: i64,
    pub deleted_count: i64,
}

impl Display for MetadataStats {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "\n\tMessage counts: recv({}) sent({}) deleted({}) queued({})\n\tBytes stored: {}",
            self.received_count,
            self.sent_count,
            self.deleted_count,
            self.received_count - self.deleted_count,
            self.received_bytes - self.sent_bytes
        )
    }
}
