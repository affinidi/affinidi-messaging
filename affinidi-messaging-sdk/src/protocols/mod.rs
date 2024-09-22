//! This module contains the implementation of the DIDComm protocols supported by the SDK.
#[derive(Default)]
pub struct Protocols {
    pub message_pickup: message_pickup::MessagePickup,
    pub trust_ping: trust_ping::TrustPing,
    pub routing: routing::Routing,
}

pub mod message_pickup;
pub mod routing;
pub mod trust_ping;

impl Protocols {
    pub fn new() -> Protocols {
        Protocols {
            message_pickup: message_pickup::MessagePickup::default(),
            trust_ping: trust_ping::TrustPing::default(),
            routing: routing::Routing::default(),
        }
    }
}
