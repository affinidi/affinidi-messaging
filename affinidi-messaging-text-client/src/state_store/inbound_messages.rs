//! Handles processing of inbound messages
use super::State;
use crate::state_store::actions::invitation::create_new_profile;
use affinidi_messaging_didcomm::{Attachment, AttachmentData, Message};
use affinidi_messaging_sdk::{protocols::Protocols, ATM};
use base64::prelude::*;
use rand::distributions::Alphanumeric;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::error;
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
struct Name {
    given: Option<String>,
    surname: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct VCard {
    n: Name,
}

#[derive(Debug, Serialize, Deserialize)]
struct ChatMessage {
    text: String,
}

/// Responsible for completing an incoming OOB Invitation flow.
/// This occurs after this client has shared a QR Code with another client.
async fn _handle_connection_setup(atm: &ATM, state: &mut State, message: &Message) {
    info!("Received connection setup message");

    // Unpack the attachment vcard if it exists
    let mut new_chat_name = if let Some(attachment) = message.attachments.as_ref() {
        if let Some(vcard) = attachment.first() {
            if let AttachmentData::Base64 { value } = &vcard.data {
                let vcard_decoded = BASE64_URL_SAFE_NO_PAD.decode(value.base64.clone()).unwrap();
                let vcard: VCard = serde_json::from_slice(&vcard_decoded).unwrap();
                info!("Received vCard: {:#?}", vcard);
                let first = if let Some(first) = vcard.n.given.as_ref() {
                    first
                } else {
                    "UNKNOWN"
                };
                let surname = if let Some(surname) = vcard.n.surname.as_ref() {
                    surname.to_string()
                } else {
                    rand::thread_rng()
                        .sample_iter(&Alphanumeric)
                        .take(4)
                        .map(char::from)
                        .collect::<String>()
                        .to_string()
                };

                format!("{} {}", first, surname)
            } else {
                format!(
                    "UNKNOWN {}",
                    rand::thread_rng()
                        .sample_iter(&Alphanumeric)
                        .take(4)
                        .map(char::from)
                        .collect::<String>()
                )
            }
        } else {
            format!(
                "UNKNOWN {}",
                rand::thread_rng()
                    .sample_iter(&Alphanumeric)
                    .take(4)
                    .map(char::from)
                    .collect::<String>()
            )
        }
    } else {
        format!(
            "UNKNOWN {}",
            rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(4)
                .map(char::from)
                .collect::<String>()
        )
    };

    // Create the new DID for this chat
    let our_new_did = create_new_profile(
        atm,
        state.settings.mediator_did.as_ref().unwrap(),
        Some(new_chat_name.clone()),
    )
    .await
    .unwrap();

    // Modify the new_chat_name so it is unique if it already exists
    if state.chat_list.chats.contains_key(&new_chat_name) {
        let split_pos = our_new_did.inner.did.char_indices().nth_back(4).unwrap().0;
        let a = &our_new_did.inner.did[split_pos..];
        new_chat_name = format!("{} {}", new_chat_name, a);
    }

    // Get the current profile
    let profiles = atm.get_profiles();

    let from: String = message.to.clone().unwrap().first().unwrap().to_string();
    let to: String = message.from.clone().unwrap();
    let new_bob = message
        .body
        .as_object()
        .unwrap()
        .get("channel_did")
        .unwrap()
        .as_str()
        .unwrap();
    info!("New DID: {}", new_bob);

    let current_profile = {
        profiles
            .read()
            .await
            .0
            .values()
            .find(|p| p.inner.did == from)
            .unwrap()
            .clone()
    };

    // Add this new profile to ATM
    let our_new_profile = atm.profile_add(&our_new_did, true).await.unwrap();
    info!("Added new profile to ATM");

    let attachment = Attachment::base64("eyJuIjp7ImdpdmVuIjoiUnVzdHkiLCJzdXJuYW1lIjoiQ2xpZW50In0sImVtYWlsIjp7InR5cGUiOnsid29yayI6InJ1c3R5QCJ9fSwidGVsIjp7InR5cGUiOnsiY2VsbCI6IjEyMzQ1Njc4In19fQ".into())
                .id(Uuid::new_v4().into())
                .description("Alice's vCard Info".into())
                .media_type("text/x-vcard".into())
                .format("https://affinidi.com/atm/client-attachment/contact-card".into())
                .finalize();

    // Create the response message
    let new_message = Message::build(
        uuid::Uuid::new_v4().to_string(),
        "https://affinidi.com/atm/client-actions/connection-accepted".to_string(),
        json!({"channel_did": our_new_did.inner.did}),
    )
    .from(from.clone())
    .pthid(message.pthid.clone().unwrap())
    .thid(message.thid.clone().unwrap())
    .to(to.clone())
    .attachment(attachment)
    .finalize();

    let packed = atm
        .pack_encrypted(
            &new_message,
            message.from.as_ref().unwrap(),
            Some(&from),
            Some(&from),
        )
        .await;

    let protocols = Protocols::default();
    let forwarded = protocols
        .routing
        .forward_message(
            atm,
            &current_profile,
            packed.unwrap().0.as_str(),
            state.settings.mediator_did.as_ref().unwrap(),
            &to,
            None,
            None,
        )
        .await;

    let _ = atm
        .send_message(
            &current_profile,
            &forwarded.as_ref().unwrap().1,
            &forwarded.as_ref().unwrap().0,
            false,
        )
        .await;

    info!("Sent connection setup response message");

    // Start cleaning up the old chat and profiles
    let Some(chat) = state.chat_list.find_chat_by_did(&current_profile.inner.did) else {
        error!("Chat not found for DID({})", &current_profile.inner.did);
        return;
    };

    // Invitation is complete
    // Remove the old invite chat
    state.remove_chat(&chat, atm).await;

    // Create the new chat with the new DID
    state
        .chat_list
        .create_chat(
            &new_chat_name,
            &format!("Chatting with {}", new_chat_name),
            &our_new_profile,
            Some(new_bob.to_string()),
            None,
        )
        .await;

    // Insert a new message into the chat
    state
        .chat_list
        .chats
        .get_mut(&new_chat_name)
        .unwrap()
        .messages
        .push(format!("Start of conversation with {}", new_chat_name));
}

pub async fn handle_message(atm: &ATM, state: &mut State, message: &Message) {
    match message.type_.as_str() {
        "https://affinidi.com/atm/client-actions/connection-setup" => {
            _handle_connection_setup(atm, state, message).await;
        }
        "https://affinidi.com/atm/client-actions/chat-activity" => {
            // Notice that someone else is typing
            /*
                Message {
                   id: "a141cca2-87ec-49b1-8f4b-5309281cb16b",
                   typ: "application/didcomm-plain+json",
                   type_: "https://affinidi.com/atm/client-actions/chat-activity",
                   body: Object {
                       "seqNo": Number(0),
                   },
                   from: Some(
                       "did:key:zDnaejpsRCMGt1HbTptCh9toKYsDrUukRshMVGBNkZYDb4Sv8",
                   ),
                   to: Some(
                       [
                           "did:key:zDnaeh4gZ787EKUUgt4Jwyq9EbVh7F4qrF3UUkQK8dTSiX43y",
                       ],
                   ),
                   thid: Some(
                       "a141cca2-87ec-49b1-8f4b-5309281cb16b",
                   ),
                   pthid: None,
                   extra_headers: {},
                   created_time: Some(
                       1733764621,
                   ),
                   expires_time: None,
                   from_prior: None,
                   attachments: None,
               }
            */
        }
        "https://affinidi.com/atm/client-actions/chat-message" => {
            // Received a chat message - need to add this to our chats

            let to_did = if let Some(to_did) = &message.to {
                to_did.first().map(|f| f.to_string())
            } else {
                None
            };

            let Some(to_did) = to_did else {
                warn!("No to DID found in message");
                return;
            };

            let Some(chat) = state.chat_list.find_chat_by_did(&to_did) else {
                warn!("Chat not found for DID({})", &to_did);
                return;
            };

            let chat_msg: ChatMessage =
                match serde_json::from_value::<ChatMessage>(message.body.clone()) {
                    Ok(msg) => msg,
                    Err(e) => {
                        warn!("Failed to parse chat message: {}", e);
                        return;
                    }
                };

            let Some(mut_chat) = state.chat_list.chats.get_mut(&chat.name) else {
                warn!("Couldn't get mutable chat({})", &chat.name);
                return;
            };

            if let Some(active_chat) = &state.chat_list.active_chat {
                if active_chat != &chat.name {
                    mut_chat.has_unread = true;
                }
            }
            mut_chat.messages.push(chat_msg.text);
        }
        "https://didcomm.org/messagepickup/3.0/status" => {
            info!("Received message pickup status message");
        }
        _ => {
            warn!("Unknown message type: {}", message.type_);
        }
    }
}
