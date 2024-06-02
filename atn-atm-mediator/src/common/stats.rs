use std::fmt::Debug;

/// Contains Mediator statistics regarding the service
#[derive(Default)]
pub struct Stats {
    /// Number of messages received by the Mediator
    pub msg_received: u64,
    /// Number of messages sent by the Mediator
    pub msg_sent: u64,
    /// Number of messages stored by the Mediator (in the database)
    pub msg_stored: u64,
}

impl Debug for Stats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stats")
            .field("msg_received", &self.msg_received)
            .field("msg_sent", &self.msg_sent)
            .field("msg_stored", &self.msg_stored)
            .finish()
    }
}
