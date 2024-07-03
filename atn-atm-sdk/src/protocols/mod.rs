#[derive(Default)]
pub struct Protocols {
    pub message_pickup: message_pickup::MessagePickup,
    pub trust_ping: trust_ping::TrustPing,
}

pub mod message_pickup;
pub mod trust_ping;
