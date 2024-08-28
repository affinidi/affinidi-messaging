use crate::ATM;

pub struct Protocols {
    pub message_pickup: message_pickup::MessagePickup,
    pub trust_ping: trust_ping::TrustPing,
}

pub mod message_pickup;
pub mod trust_ping;

impl Protocols {
    pub fn new() -> Protocols {
        Protocols {
            message_pickup: message_pickup::MessagePickup::new(),
            trust_ping: trust_ping::TrustPing::default(),
        }
    }
}
