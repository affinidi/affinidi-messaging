//! Handles processing of inbound messages
use super::State;
use crate::state_store::actions::chat_list::ChatStatus;
use crate::state_store::actions::invitation::create_new_profile;
use crate::state_store::chat_message::{ChatEffect, ChatMessage, ChatMessageType};
use affinidi_messaging_didcomm::{Attachment, AttachmentData, Message, UnpackMetadata};
use affinidi_messaging_sdk::protocols::message_pickup::{MessagePickup, MessagePickupStatusReply};
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
struct VcardType {
    r#type: VcardTypes,
}

#[derive(Debug, Serialize, Deserialize)]
enum VcardTypes {
    #[serde(rename = "work")]
    Work(String),
    #[serde(rename = "cell")]
    Cell(String),
}
#[derive(Debug, Serialize, Deserialize)]
struct VCard {
    n: Name,
    email: Option<VcardType>,
    tel: Option<VcardType>,
}

#[derive(Serialize, Deserialize, Debug)]
struct _ChatMessage {
    pub text: Option<String>,
    pub effect: Option<String>,
}

/// Responsible for completing an incoming OOB Invitation flow.
/// This occurs after this client has shared a QR Code with another client.
async fn _handle_connection_setup(
    atm: &ATM,
    state: &mut State,
    message: &Message,
    meta: &UnpackMetadata,
) {
    info!("Received connection setup message");

    // Unpack the attachment vcard if it exists
    let mut new_chat_name = if let Some(attachment) = message.attachments.as_ref() {
        if let Some(vcard) = attachment.first() {
            if let AttachmentData::Base64 { value } = &vcard.data {
                let vcard_decoded = BASE64_URL_SAFE_NO_PAD.decode(value.base64.clone()).unwrap();
                let vcard: VCard = serde_json::from_slice(&vcard_decoded).unwrap();
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
        true,
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

    let vcard = VCard {
        n: Name {
            given: Some(state.settings.our_name.clone().unwrap()),
            surname: Some(String::new()),
        },
        email: Some(VcardType {
            r#type: VcardTypes::Work(String::new()),
        }),
        tel: Some(VcardType {
            r#type: VcardTypes::Cell(String::new()),
        }),
    };
    let vcard = serde_json::to_string(&vcard).unwrap();
    let attachment = Attachment::base64(BASE64_URL_SAFE_NO_PAD.encode(vcard))
        .id(Uuid::new_v4().into())
        .description(format!(
            "{}'s vCard Info",
            state.settings.our_name.clone().unwrap()
        ))
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
    let _ = MessagePickup::default()
        .send_messages_received(
            atm,
            &current_profile,
            &vec![meta.sha256_hash.clone()],
            false,
        )
        .await;

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
            ChatStatus::EstablishedChannel,
        )
        .await;

    // Insert a new message into the chat
    state
        .chat_list
        .chats
        .get_mut(&new_chat_name)
        .unwrap()
        .messages
        .push(ChatMessage::new(
            ChatMessageType::Effect {
                effect: ChatEffect::System,
            },
            format!("Start of conversation with {}", new_chat_name),
        ));

    if state.chat_list.active_chat.is_none() {
        state.chat_list.active_chat = Some(new_chat_name.clone());
    }
}

pub async fn handle_message(
    atm: &ATM,
    state: &mut State,
    message: &Message,
    meta: &UnpackMetadata,
) {
    let to_did = if let Some(to) = &message.to {
        if let Some(to) = to.first() {
            to.to_string()
        } else {
            warn!("No to DID found in message");
            return;
        }
    } else {
        warn!("No to DID found in message");
        return;
    };

    let profile = {
        if let Some(profile) = atm.get_profiles().read().await.find_by_did(&to_did) {
            profile
        } else {
            warn!("Profile not found for DID({})", &to_did);
            return;
        }
    };

    let Some(chat) = state.chat_list.find_chat_by_did(&to_did) else {
        warn!("Chat not found for DID({})", &to_did);
        return;
    };

    match message.type_.as_str() {
        "https://affinidi.com/atm/client-actions/connection-setup" => {
            // Completes an inbound OOB Invitation flow (after sharing a QR Code)
            _handle_connection_setup(atm, state, message, meta).await;
            return; // message was deleted in the function
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
        "https://affinidi.com/atm/client-actions/chat-message" => 'label_break: {
            // Received a chat message - need to add this to our chats
            let chat_msg: _ChatMessage =
                match serde_json::from_value::<_ChatMessage>(message.body.clone()) {
                    Ok(msg) => msg,
                    Err(e) => {
                        warn!("Failed to parse chat message: {}", e);
                        break 'label_break;
                    }
                };

            let Some(mut_chat) = state.chat_list.chats.get_mut(&chat.name) else {
                warn!("Couldn't get mutable chat({})", &chat.name);
                break 'label_break;
            };

            if let Some(active_chat) = &state.chat_list.active_chat {
                if active_chat != &chat.name {
                    mut_chat.has_unread = true;
                }
            }
            mut_chat.messages.push(ChatMessage::new(
                ChatMessageType::Inbound,
                chat_msg.text.unwrap(),
            ));
        }
        "https://didcomm.org/messagepickup/3.0/status" => 'label_break: {
            if chat.initialization {
                // Check if we have any messages waiting to be picked up
                let Ok(status) =
                    serde_json::from_value::<MessagePickupStatusReply>(message.body.clone())
                else {
                    warn!("Failed to parse message pickup status message");
                    break 'label_break;
                };
                info!(
                    "Profile ({}) has ({}) messages waiting",
                    &profile.inner.alias, status.message_count
                );

                let msg_pickup = MessagePickup::default();
                if status.message_count > 0 {
                    let _ = msg_pickup
                        .send_delivery_request(
                            atm,
                            &profile,
                            Some(status.message_count as usize),
                            false,
                        )
                        .await;
                }

                let mut_chat = state.chat_list.chats.get_mut(&chat.name).unwrap();
                mut_chat.initialization = false;
            }
            return; // Ephemeral status message - no need to delete it
        }
        "https://affinidi.com/atm/client-actions/chat-delivered" => {
            /*
                Message {
                    id: "62f8bffb-fde5-4e04-841e-de7fc98e248e",
                    typ: "application/didcomm-plain+json",
                    type_: "https://affinidi.com/atm/client-actions/chat-delivered",
                    body: Object {
                        "messages": Array [
                            String("1c7b9964-92f0-430c-8ec9-6bbe852d0e4d"),
                        ],
                    },
                    from: Some(
                        "did:key:zDnaetp9QPxuWUBtfTfjsKPEfCo8p9BiWg1buNaS5LTEsEz75",
                    ),
                    to: Some(
                        [
                            "did:key:zDnaef5UtAgL3Nayo7aWLkWh86EuMfkW5Vio6DvNN86U5QxcZ",
                        ],
                    ),
                    thid: Some(
                        "62f8bffb-fde5-4e04-841e-de7fc98e248e",
                    ),
                    pthid: None,
                    extra_headers: {},
                    created_time: Some(
                        1733846313,
                    ),
                    expires_time: None,
                    from_prior: None,
                    attachments: None,
                }
            */
        }
        "https://affinidi.com/atm/client-actions/chat-effect" => 'label_break: {
            let chat_msg: _ChatMessage =
                match serde_json::from_value::<_ChatMessage>(message.body.clone()) {
                    Ok(msg) => msg,
                    Err(e) => {
                        warn!("Failed to parse chat message: {}", e);
                        break 'label_break;
                    }
                };

            let Some(mut_chat) = state.chat_list.chats.get_mut(&chat.name) else {
                warn!("Couldn't get mutable chat({})", &chat.name);
                break 'label_break;
            };

            if let Some(active_chat) = &state.chat_list.active_chat {
                if active_chat != &chat.name {
                    mut_chat.has_unread = true;
                }
            }

            let effect = match chat_msg.effect.unwrap().as_str() {
                "balloons" => ChatEffect::Ballons,
                "confetti" => ChatEffect::Confetti,
                _ => ChatEffect::System,
            };
            mut_chat.messages.push(ChatMessage::new(
                ChatMessageType::Effect { effect },
                String::new(),
            ));
        }
        "https://didcomm.org/messagepickup/3.0/delivery" => {
            // Received a message pickup delivery message
            if let Some(attachments) = &message.attachments {
                for attachment in attachments {
                    match &attachment.data {
                        AttachmentData::Base64 { value } => {
                            let decoded = match BASE64_URL_SAFE_NO_PAD.decode(value.base64.clone())
                            {
                                Ok(decoded) => match String::from_utf8(decoded) {
                                    Ok(decoded) => decoded,
                                    Err(e) => {
                                        warn!(
                                                "Error encoding vec[u8] to string: ({:?}). Attachment ID ({:?})",
                                                e, attachment.id
                                            );
                                        continue;
                                    }
                                },
                                Err(e) => {
                                    warn!(
                                        "Error decoding base64: ({:?}). Attachment ID ({:?})",
                                        e, attachment.id
                                    );
                                    continue;
                                }
                            };

                            match atm.unpack(&decoded).await {
                                Ok((mut m, meta)) => {
                                    info!("Delivered message: id({:?})\n {:#?}", attachment.id, m);
                                    if let Some(attachment_id) = &attachment.id {
                                        m.id = attachment_id.to_string();
                                    }
                                    Box::pin(handle_message(atm, state, &m, &meta)).await;
                                }
                                Err(e) => {
                                    warn!("Error unpacking message: ({:?})", e);
                                    continue;
                                }
                            };
                        }
                        _ => {
                            warn!("Attachment type not supported: {:?}", attachment.data);
                            continue;
                        }
                    };
                }
            }
            return; // ephemeral status message - no need to delete it
        }
        _ => {
            warn!("Unknown message type: {}", message.type_);
        }
    }
    // Do we need to delete the message after processing?
    match MessagePickup::default()
        .send_messages_received(atm, &profile, &vec![meta.sha256_hash.clone()], false)
        .await
    {
        Ok(_) => info!("Deleted message ({})", message.id),
        Err(err) => error!("Failed to delete message ({}) - {:?}", message.id, err),
    }
}
