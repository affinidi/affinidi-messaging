use std::fmt::{self, Display, Formatter};

pub mod handlers;

#[derive(Clone)]
pub struct DatabaseHandler {
    pub pool: deadpool_redis::Pool,
}

/// Statistics for the mediator
#[derive(Default, Debug)]
pub struct MetadataStats {
    pub message_count: u64,
    pub bytes_stored: u64,
    pub did_count: u64,
}

impl MetadataStats {
    pub fn new() -> Self {
        Self {
            message_count: 0,
            bytes_stored: 0,
            did_count: 0,
        }
    }
}

impl Display for MetadataStats {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "\n\tMessage count: {}\n\tBytes stored: {}\n\tDID count: {}",
            self.message_count, self.bytes_stored, self.did_count
        )
    }
}
