use affinidi_messaging_didcomm::{Attachment, Message, MessageBuilder};
use affinidi_messaging_sdk::{
    ATM, messages::SuccessResponse, profiles::ATMProfile, protocols::Protocols,
};
use affinidi_tdk::secrets_resolver::secrets::{Secret, SecretMaterial, SecretType};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use image::Luma;
use qrcode::QrCode;
use ratatui::{
    style::{Color, Modifier, Style},
    text::{Line, Span},
};
use serde_json::json;
use ssi::{JWK, dids::DIDKey, jwk::Params};
use std::{
    fmt::{self, Debug, Formatter},
    sync::Arc,
};
use tokio::sync::mpsc::UnboundedSender;
use tracing::warn;
use uuid::Uuid;

use crate::state_store::{
    State,
    inbound_messages::{Name, VCard},
};

use super::chat_list::ChatStatus;

#[derive(Clone, Default)]
pub struct Invite {
    pub invite_url: String,
    pub invite_profile: Option<Arc<ATMProfile>>,
    pub qr_code: Option<image::ImageBuffer<Luma<u8>, Vec<u8>>>,
}

impl Debug for Invite {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Invite")
            .field("invite_url", &self.invite_url)
            .field("invite_profile", &self.invite_profile)
            .finish()
    }
}

#[derive(Clone, Debug, Default)]
pub struct InvitePopupState {
    pub show_invite_popup: bool,
    pub invite: Option<Invite>,
    pub invite_error: Option<String>,
    pub messages: Vec<Line<'static>>,
}

/// Helper function to create a new profile with a random DID and add it to the mediator
/// atm: Affinidi Text Messenger instance
/// mediator_did: Mediator DID to connect to
/// alias: Optional alias for the profile
/// alias_suffix: Whether to add a suffix to the alias (last 4 character of the DID)
pub async fn create_new_profile(
    atm: &ATM,
    mediator_did: &str,
    alias: Option<String>,
    alias_suffix: bool,
    state: &mut State,
) -> anyhow::Result<ATMProfile> {
    let secp256k1_key = JWK::generate_secp256k1();
    let did_key = DIDKey::generate(&secp256k1_key).unwrap();

    let (curve, d, x, y) = match secp256k1_key.clone().params {
        Params::EC(map) => (
            String::from(map.curve.clone().unwrap()),
            String::from(map.ecc_private_key.clone().unwrap()),
            String::from(map.x_coordinate.clone().unwrap()),
            String::from(map.y_coordinate.clone().unwrap()),
        ),
        _ => {
            panic!("Failed to generate secp256k1 key")
        }
    };

    let secret = Secret {
        id: format!("{}#{}", did_key, did_key.to_string().split_at(8).1),
        type_: SecretType::JsonWebKey2020,
        secret_material: SecretMaterial::JWK {
            private_key_jwk: json!({
                "crv": curve,
                "d":  d,
                "kty": "EC",
                "x": x,
                "y": y
            }),
        },
    };

    let mut alias = if let Some(alias) = alias {
        alias
    } else {
        format!(
            "Invite {}",
            &did_key.to_string()[did_key.to_string().char_indices().nth_back(3).unwrap().0..]
        )
    };

    if alias_suffix {
        alias.push_str(&format!(
            " {}",
            &did_key.to_string()[did_key.to_string().char_indices().nth_back(3).unwrap().0..]
        ));
    }

    atm.add_secret(&secret);
    state.add_secret(secret);
    match ATMProfile::new(
        atm,
        Some(alias),
        did_key.to_string(),
        Some(mediator_did.to_string()),
    )
    .await
    {
        Ok(profile) => Ok(profile),
        Err(e) => {
            warn!("Failed to create new profile: {}", e);
            Err(e.into())
        }
    }
}

/// Given an OOB Invitation link, this will send an accept message to the inviter
pub async fn send_invitation_accept(
    state: &mut State,
    state_tx: &UnboundedSender<State>,
    atm: &ATM,
) -> anyhow::Result<()> {
    // Fetch the Invite message
    let body = reqwest::get(&state.accept_invite_popup.invite_link)
        .await?
        .text()
        .await?;

    state
        .accept_invite_popup
        .messages
        .push(Line::from(Span::styled(
            format!(
                "Fetched OOB Invite from remote link: {}",
                &state.accept_invite_popup.invite_link
            ),
            Style::default().fg(Color::LightBlue),
        )));
    state_tx.send(state.clone())?;

    // Parse the message
    let parsed_body: SuccessResponse<String> = match serde_json::from_str(&body) {
        Ok(parsed_body) => parsed_body,
        Err(e) => {
            warn!("Failed to parse OOB Invite: {}", e);
            return Ok(());
        }
    };

    let Some(base64_invite) = parsed_body.data else {
        warn!("Failed to parse OOB Invite: No data found");
        return Ok(());
    };

    let invite = if let Ok(invite) = BASE64_URL_SAFE_NO_PAD.decode(base64_invite) {
        String::from_utf8(invite).unwrap()
    } else {
        warn!("Bas64 decoding failed on invite!");
        return Ok(());
    };

    let invite_message = match serde_json::from_str::<Message>(&invite) {
        Ok(invite_message) => invite_message,
        Err(e) => {
            warn!("Failed to parse OOB Invite message: {}", e);
            return Ok(());
        }
    };

    let Some(mediator_did) = state.settings.mediator_did.clone() else {
        warn!("Mediator DID is not set");
        return Ok(());
    };

    let Some(invite_did) = invite_message.from else {
        warn!("Invite message is missing 'from' field");
        return Ok(());
    };
    let invite_did_suffix = invite_did.split_at(invite_did.len() - 4).1;

    state
        .accept_invite_popup
        .messages
        .push(Line::from(Span::styled(
            format!("Invitation originated from Remote DID ({}).", invite_did),
            Style::default().fg(Color::LightBlue),
        )));
    state_tx.send(state.clone())?;

    // Create a new temporary profile for the invitation
    let accept_temp_profile = create_new_profile(
        atm,
        &mediator_did,
        Some(format!("Ephemeral Accept {}", invite_did_suffix)),
        true,
        state,
    )
    .await?;
    let accept_temp_profile = atm.profile_add(&accept_temp_profile, true).await?;

    state
        .chat_list
        .create_chat(
            &format!(
                "Ephemeral OOB Accept {} {}",
                invite_did_suffix,
                accept_temp_profile
                    .inner
                    .did
                    .split_at(accept_temp_profile.inner.did.len() - 4)
                    .1
            ),
            &format!(
                "Ephemeral DID used to setup Secure Chat: {}",
                accept_temp_profile.inner.did
            ),
            &accept_temp_profile,
            Some(invite_did.clone()),
            Some(state.accept_invite_popup.invite_link.clone()),
            ChatStatus::EphemeralAcceptInvite,
        )
        .await;

    /*let our_ephemeral_chat = state
        .chat_list
        .find_chat_by_did(&accept_temp_profile.inner.did)
        .unwrap();
    let mut_our_ephemeral_chat = state
        .chat_list
        .chats
        .get_mut(&our_ephemeral_chat.name)
        .unwrap();
    //mut_our_ephemeral_chat.messages.push(Line::from())
    */

    state
        .accept_invite_popup
        .messages
        .push(Line::from(Span::styled(
            format!(
                "Our Ephemeral invite DID ({}) to accept invite.",
                &accept_temp_profile.inner.did
            ),
            Style::default().fg(Color::LightBlue),
        )));
    state_tx.send(state.clone())?;

    // Create a new secure profile for the established chat channel
    let accept_secure_profile = create_new_profile(
        atm,
        &mediator_did,
        Some(format!("Secure Accept {}", invite_did_suffix)),
        true,
        state,
    )
    .await?;
    let accept_secure_profile = atm.profile_add(&accept_secure_profile, true).await?;

    state
        .chat_list
        .create_chat(
            &format!(
                "Secure Channel OOB Accept {} {}",
                invite_did_suffix,
                accept_secure_profile
                    .inner
                    .did
                    .split_at(accept_secure_profile.inner.did.len() - 4)
                    .1
            ),
            &format!(
                "Secure Channel DID used for Secure Chat: {}",
                accept_secure_profile.inner.did
            ),
            &accept_secure_profile,
            None,
            Some(state.accept_invite_popup.invite_link.clone()),
            ChatStatus::AwaitingInvitationAcceptance,
        )
        .await;
    state
        .accept_invite_popup
        .messages
        .push(Line::from(Span::styled(
            format!(
                "Our Secure future Chat DID ({}) to use when invite process is completed.",
                &accept_secure_profile.inner.did
            ),
            Style::default().fg(Color::LightBlue),
        )));
    state_tx.send(state.clone())?;

    let Some(c) = state
        .chat_list
        .find_chat_by_did(&accept_temp_profile.inner.did)
    else {
        warn!(
            "Failed to find chat by DID: {}",
            &accept_temp_profile.inner.did
        );
        return Ok(());
    };

    if let Some(mut_chat) = state.chat_list.chats.get_mut(&c.name) {
        mut_chat.hidden = Some(accept_secure_profile.inner.did.clone());
    }

    // Create the vcard
    let vcard = VCard {
        n: Name {
            given: state.settings.our_name.clone(),
            surname: None,
        },
        email: None,
        tel: None,
    };

    let attachment =
        Attachment::base64(BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_string(&vcard).unwrap()))
            .id(Uuid::new_v4().to_string())
            .description("vCard Info".into())
            .media_type("text/x-vcard".into())
            .format("https://affinidi.com/atm/client-attachment/contact-card".into())
            .finalize();

    // Create response message
    let accept_message_id = Uuid::new_v4();
    let accept_message = MessageBuilder::new(
        accept_message_id.to_string(),
        "https://affinidi.com/atm/client-actions/connection-setup".to_string(),
        json!({"channel_did": accept_secure_profile.inner.did.clone()}),
    )
    .from(accept_temp_profile.inner.did.clone())
    .to(invite_did.clone())
    .attachment(attachment)
    .thid(accept_message_id.to_string())
    .pthid(invite_message.id)
    .finalize();

    let packed = atm
        .pack_encrypted(
            &accept_message,
            &invite_did,
            Some(&accept_temp_profile.inner.did.clone()),
            Some(&accept_temp_profile.inner.did.clone()),
        )
        .await?;

    // Send the response message
    atm.forward_and_send_message(
        &accept_temp_profile,
        &packed.0,
        None,
        &mediator_did,
        &invite_did,
        None,
        None,
        false,
    )
    .await?;

    state
        .accept_invite_popup
        .messages
        .push(Line::from(Span::styled(
            format!(
                "Successfully sent connection-setup message to remote DID: {}",
                &invite_did
            ),
            Style::default().fg(Color::LightBlue),
        )));
    state_tx.send(state.clone())?;

    Ok(())
}

pub async fn create_invitation(
    state: &mut State,
    state_tx: &UnboundedSender<State>,
    atm: &ATM,
) -> anyhow::Result<()> {
    let protocols = Protocols::default();

    state.invite_popup.show_invite_popup = true;
    state.invite_popup.invite_error = None;
    state.invite_popup.messages.clear();
    // Send the state immediately so we render the popup while waiting for the rest to complete
    state_tx.send(state.clone())?;
    if let Some(mediator_did) = state.settings.mediator_did.clone() {
        match create_new_profile(atm, &mediator_did, None, false, state).await {
            Ok(profile) => {
                state.invite_popup.messages.push(Line::from(vec![
                    Span::styled(
                        "Temporary invite DID created: ",
                        Style::default().fg(Color::Green),
                    ),
                    Span::styled(
                        profile.inner.did.clone(),
                        Style::default()
                            .add_modifier(Modifier::BOLD)
                            .fg(Color::Blue),
                    ),
                ]));
                state.invite_popup.messages.push(Line::from(Span::styled(
                    "Attempting initial authentication to mediator...",
                    Style::default().fg(Color::LightBlue),
                )));
                state_tx.send(state.clone())?;

                // Add profile to the mediator
                match atm.profile_add(&profile, true).await {
                    Ok(profile) => {
                        state.invite_popup.messages.push(Line::from(vec![
                            Span::styled(
                                "Successfully connected to mediator: ",
                                Style::default().fg(Color::Green),
                            ),
                            Span::styled(
                                mediator_did,
                                Style::default()
                                    .add_modifier(Modifier::BOLD)
                                    .fg(Color::Blue),
                            ),
                        ]));
                        state.invite_popup.messages.push(Line::from(Span::styled(
                            "Asking Mediator for OOB Invitation link...",
                            Style::default().fg(Color::LightBlue),
                        )));
                        state_tx.send(state.clone())?;

                        // Get the OOB Invite itself
                        match protocols
                            .oob_discovery
                            .create_invite(atm, &profile, None)
                            .await
                        {
                            Ok(invite) => {
                                state.invite_popup.messages.push(Line::from(Span::styled(
                                    "OOB Invite Link successfully created",
                                    Style::default().fg(Color::Green),
                                )));

                                let url = format!(
                                    "{}/oob?_oobid={}",
                                    profile.get_mediator_rest_endpoint().unwrap(),
                                    invite
                                );

                                let code = QrCode::new(url.as_bytes())?;

                                // Render the bits into an image.
                                let qr_code: image::ImageBuffer<Luma<u8>, Vec<u8>> =
                                    code.render::<Luma<u8>>().build();
                                // DynamicImage::ImageLuma8(code.render::<Luma<u8>>().build());

                                state.invite_popup.invite = Some(Invite {
                                    invite_url: url.clone(),
                                    invite_profile: Some(profile.clone()),
                                    qr_code: Some(qr_code),
                                });

                                state
                                    .chat_list
                                    .create_chat(
                                        &profile.inner.alias,
                                        &format!(
                                            "OOB Invite stage 1. Ephemeral DID: {}",
                                            profile.inner.did
                                        ),
                                        &profile,
                                        None,
                                        Some(url.clone()),
                                        ChatStatus::AwaitingInvitationAcceptance,
                                    )
                                    .await;
                            }
                            Err(e) => {
                                state.invite_popup.invite_error =
                                    Some(format!("Failed to create OOB Invite: {}", e));
                            }
                        }
                    }
                    Err(e) => {
                        state.invite_popup.invite_error =
                            Some(format!("Failed to add profile to mediator: {}", e));
                    }
                };
            }
            Err(e) => {
                state.invite_popup.invite_error = Some(e.to_string());
            }
        }
    } else {
        state.invite_popup.invite_error = Some("Mediator DID is not set".to_string());
    }

    Ok(())
}
