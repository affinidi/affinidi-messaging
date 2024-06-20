use std::fmt::{self, Display, Formatter};

pub mod delete;
pub mod fetch;
pub mod get;
pub mod handlers;
pub mod list;
pub mod session;
pub mod stats;
pub mod store;

#[derive(Clone)]
pub struct DatabaseHandler {
    pub pool: deadpool_redis::Pool,
}

/// Statistics for the mediator
#[derive(Default, Debug)]
pub struct MetadataStats {
    pub received_bytes: i64,  // Total number of bytes processed
    pub sent_bytes: i64,      // Total number of bytes sent
    pub deleted_bytes: i64,   // Total number of bytes deleted
    pub received_count: i64,  // Total number of messages received
    pub sent_count: i64,      // Total number of messages sent
    pub deleted_count: i64,   // Total number of messages deleted
    pub websocket_open: i64,  // Total number of websocket connections opened
    pub websocket_close: i64, // Total number of websocket connections closed
}

impl Display for MetadataStats {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "\n\tMessage counts: recv({}) sent({}) deleted({}) queued({})\n\tStorage: received({}), sent({}), deleted({}), current_queued({})\n\tWebsocket connections: open({}) close({}) current({})\n",
            self.received_count,
            self.sent_count,
            self.deleted_count,
            self.received_count - self.deleted_count,
            self.received_bytes,
            self.sent_bytes,
            self.deleted_bytes,
            self.received_bytes - self.deleted_bytes,
            self.websocket_open,
            self.websocket_close,
            self.websocket_open - self.websocket_close,
        )
    }
}
