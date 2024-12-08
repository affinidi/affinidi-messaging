//! Handles processing of inbound messages

use affinidi_messaging_didcomm::{Message, UnpackMetadata};
use affinidi_messaging_sdk::ATM;
use tracing::{info, warn};

use super::State;

pub fn handle_message(atm: &ATM, state: &mut State, message: &Message, meta: &UnpackMetadata) {
    match message.type_.as_str() {
        "https://affinidi.com/atm/client-actions/connection-setup" => {
            info!("Received connection setup message");
        }
        "https://didcomm.org/messagepickup/3.0/status" => {
            info!("Received message pickup status message");
        }
        _ => {
            warn!("Unknown message type: {}", message.type_);
        }
    }
}
