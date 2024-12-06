use std::{
    fmt::{self, Debug, Formatter},
    sync::Arc,
};

use affinidi_messaging_sdk::{
    profiles::Profile,
    protocols::Protocols,
    secrets::{Secret, SecretMaterial, SecretType},
    ATM,
};
use image::Luma;
use qrcode::QrCode;
use ratatui::{
    style::{Color, Modifier, Style},
    text::{Line, Span},
};
use serde_json::json;
use ssi::{dids::DIDKey, jwk::Params, JWK};
use tokio::sync::mpsc::UnboundedSender;
use tracing::warn;

use crate::state_store::State;

#[derive(Clone, Default)]
pub struct Invite {
    pub invite_url: String,
    pub invite_profile: Option<Arc<Profile>>,
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

pub async fn create_new_profile(atm: &ATM, mediator_did: &str) -> anyhow::Result<Profile> {
    let p256_key = JWK::generate_p256();
    let did_key = DIDKey::generate(&p256_key).unwrap();

    let (d, x, y) = if let Params::EC(map) = p256_key.clone().params {
        (
            String::from(map.ecc_private_key.clone().unwrap()),
            String::from(map.x_coordinate.clone().unwrap()),
            String::from(map.y_coordinate.clone().unwrap()),
        )
    } else {
        panic!("Failed to generate P256 key")
    };

    let secret = Secret {
        id: format!("{}#{}", did_key, did_key.to_string().split_at(8).1),
        type_: SecretType::JsonWebKey2020,
        secret_material: SecretMaterial::JWK {
            private_key_jwk: json!({
                "crv": "P-256",
                "d":  d,
                "kty": "EC",
                "x": x,
                "y": y
            }),
        },
    };

    match Profile::new(
        atm,
        Some(format!(
            "Invite-{}",
            &did_key.to_string()[did_key.to_string().char_indices().nth_back(3).unwrap().0..]
        )),
        did_key.to_string(),
        Some(mediator_did.to_string()),
        vec![secret],
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
        match create_new_profile(atm, &mediator_did).await {
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
                                    invite_url: url,
                                    invite_profile: Some(profile.clone()),
                                    qr_code: Some(qr_code),
                                });
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
