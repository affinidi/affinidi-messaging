#[derive(Default)]
pub struct Protocols {
    pub message_pickup: message_pickup::MessagePickup,
}

pub mod message_pickup;
