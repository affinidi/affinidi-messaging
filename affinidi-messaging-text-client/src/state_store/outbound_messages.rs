use std::time::SystemTime;

use affinidi_messaging_didcomm::MessageBuilder;
use affinidi_messaging_sdk::ATM;
use serde_json::json;
use tracing::{info, warn};
use uuid::Uuid;

use super::State;

/// Takes a chat_msg and sends it to the right
pub(crate) async fn send_message(state: &mut State, atm: &ATM, chat_msg: &str) {
    let Some(active_chat) = &state.chat_list.active_chat else {
        warn!("No active chat to send message to");
        return;
    };

    let Some(chat) = state.chat_list.find_chat_by_name(active_chat) else {
        warn!("Active chat ({}) not found in chat list", active_chat);
        return;
    };

    let Some(remote_did) = chat.remote_did.as_ref() else {
        warn!("Remote DID not found for Chat ({})", active_chat);
        return;
    };

    let profiles = atm.get_profiles();

    let our_profile = {
        let Some(our_profile) = profiles.read().await.find_by_did(&chat.our_profile.did) else {
            warn!("Our profile not found in Chat ({})", active_chat);
            return;
        };
        our_profile
    };

    let (our_did, mediator_did) = our_profile.dids().unwrap();

    // Create the message
    let id = Uuid::new_v4();
    let msg = MessageBuilder::new(
        id.to_string(),
        "https://affinidi.com/atm/client-actions/chat-message".into(),
        json!({"text": chat_msg}),
    )
    .from(our_did.to_string())
    .to(remote_did.to_string())
    .thid(id.to_string())
    .created_time(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .finalize();

    // Pack the message
    let (packed, _) = match atm
        .pack_encrypted(&msg, remote_did, Some(our_did), Some(our_did))
        .await
    {
        Ok(packed) => packed,
        Err(e) => {
            warn!("Failed to pack message: {}", e);
            return;
        }
    };

    let Some(mut_chat) = state.chat_list.chats.get_mut(&chat.name) else {
        warn!("Couldn't get mutable chat({})", &chat.name);
        return;
    };

    // Forward wrap and send the message
    match atm
        .forward_and_send_message(
            &our_profile,
            &packed,
            None,
            mediator_did,
            remote_did,
            None,
            None,
            false,
        )
        .await
    {
        Ok(_) => {
            // Update the chat with the new message
            mut_chat.messages.push(format!(">> Sent: {}", chat_msg));
        }
        Err(e) => {
            mut_chat
                .messages
                .push(format!(">> ERROR SENDING: {}", chat_msg));
            warn!("Failed to send message: {}", e);
        }
    }
}