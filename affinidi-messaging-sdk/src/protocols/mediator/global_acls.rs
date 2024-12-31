use super::mediator::Mediator;
use crate::{errors::ATMError, profiles::Profile, transports::SendMessageResponse, ATM};
use affinidi_messaging_didcomm::{Message, PackEncryptedOptions};
use bitfield_struct::bitfield;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    fmt::{self, Display},
    sync::Arc,
    time::SystemTime,
};
use tracing::{debug, span, Instrument, Level};
use uuid::Uuid;

/// DIDComm message body for requesting a set of Global ACLs for a list of DID Hashes
#[derive(Serialize, Deserialize)]
pub enum MediatorGlobalACLRequest {
    #[serde(rename = "acl_get")]
    GetACL(Vec<String>),
}

/// DIDComm message body for responding with a set of Global ACLs for a list of DID Hashes
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "acl_response")]
pub struct MediatorGlobalACLResponse {
    pub acl_response: Vec<GlobalACLConfig>,
    pub mediator_acl_mode: GlobalACLMode,
}

/// ACL Configuration for a DID
#[derive(Debug, Serialize, Deserialize)]
pub struct GlobalACLConfig {
    pub did_hash: String,
    pub acl_value: u32,
    pub acls: GlobalACLSet,
}

/// The ACL Set for a DID
/// Each boolean value is a single bit
/// First field starts at least significant bits
#[bitfield(u32)]
#[derive(Serialize, Deserialize)]
pub struct GlobalACLSet {
    pub forward_from: bool,
    pub forward_to: bool,
    pub inbound: bool,
    pub outbound: bool,
    pub local: bool,
    #[bits(default = true)]
    pub blocked: bool,
    pub create_invites: bool,
    pub self_admin: bool,
    /// These are reserved bits for future use
    #[bits(24, default = 0)]
    reserved: usize,
}

impl GlobalACLSet {
    /// Converts an ACL string set (ALLOW_ALL, DENY_ALL etc) to a GlobalACLSet
    pub fn from_acl_string(acls: &str, acl_mode: GlobalACLMode) -> Result<GlobalACLSet, ATMError> {
        let acls = acls.to_ascii_lowercase();

        let mut acl_bits = GlobalACLSet::default();
        for acl in acls.split(',') {
            let acl = acl.trim();

            match acl {
                "allow_all" => {
                    if acl_mode == GlobalACLMode::ExplicitDeny {
                        // setting all to false
                        acl_bits.set_forward_from(false);
                        acl_bits.set_forward_to(false);
                        acl_bits.set_inbound(false);
                        acl_bits.set_outbound(false);
                        acl_bits.set_local(false);
                        acl_bits.set_blocked(false);
                        acl_bits.set_create_invites(false);
                        acl_bits.set_self_admin(false);
                    } else {
                        // setting all to true as we are in Explicit Allow mode
                        acl_bits.set_forward_from(true);
                        acl_bits.set_forward_to(true);
                        acl_bits.set_inbound(true);
                        acl_bits.set_outbound(true);
                        acl_bits.set_local(true);
                        acl_bits.set_blocked(true);
                        acl_bits.set_create_invites(true);
                        acl_bits.set_self_admin(true);
                    }
                }
                "deny_all" => {
                    if acl_mode == GlobalACLMode::ExplicitDeny {
                        // setting all to true
                        acl_bits.set_forward_from(true);
                        acl_bits.set_forward_to(true);
                        acl_bits.set_inbound(true);
                        acl_bits.set_outbound(true);
                        acl_bits.set_local(true);
                        acl_bits.set_blocked(true);
                        acl_bits.set_create_invites(true);
                        acl_bits.set_self_admin(true);
                    } else {
                        // setting all to false as we are in Explicit Allow mode
                        acl_bits.set_forward_from(false);
                        acl_bits.set_forward_to(false);
                        acl_bits.set_inbound(false);
                        acl_bits.set_outbound(false);
                        acl_bits.set_local(false);
                        acl_bits.set_blocked(false);
                        acl_bits.set_create_invites(false);
                        acl_bits.set_self_admin(false);
                    }
                }
                "allow_local" => {
                    acl_bits.set_local(acl_mode != GlobalACLMode::ExplicitDeny);
                }
                "deny_local" => {
                    acl_bits.set_local(acl_mode == GlobalACLMode::ExplicitDeny);
                }
                "allow_forward_from" => {
                    acl_bits.set_forward_from(acl_mode != GlobalACLMode::ExplicitDeny);
                }
                "deny_forward_from" => {
                    acl_bits.set_forward_from(acl_mode == GlobalACLMode::ExplicitDeny);
                }
                "allow_forward_to" => {
                    acl_bits.set_forward_to(acl_mode != GlobalACLMode::ExplicitDeny);
                }
                "deny_forward_to" => {
                    acl_bits.set_forward_to(acl_mode == GlobalACLMode::ExplicitDeny);
                }
                "allow_inbound" => {
                    acl_bits.set_inbound(acl_mode != GlobalACLMode::ExplicitDeny);
                }
                "deny_inbound" => {
                    acl_bits.set_inbound(acl_mode == GlobalACLMode::ExplicitDeny);
                }
                "allow_outbound" => {
                    acl_bits.set_outbound(acl_mode != GlobalACLMode::ExplicitDeny);
                }
                "deny_outbound" => {
                    acl_bits.set_outbound(acl_mode == GlobalACLMode::ExplicitDeny);
                }
                "allow_create_invites" => {
                    acl_bits.set_create_invites(acl_mode != GlobalACLMode::ExplicitDeny);
                }
                "deny_create_invites" => {
                    acl_bits.set_create_invites(acl_mode == GlobalACLMode::ExplicitDeny);
                }
                "allow_self_admin" => {
                    acl_bits.set_self_admin(acl_mode != GlobalACLMode::ExplicitDeny);
                }
                "deny_self_admin" => {
                    acl_bits.set_self_admin(acl_mode == GlobalACLMode::ExplicitDeny);
                }
                _ => {
                    return Err(ATMError::ConfigError(format!(
                        "Invalid ACL String ({})",
                        acl
                    )));
                }
            }
        }
        Ok(acl_bits)
    }
}

/// Strings that can be used to set ACL's
#[derive(Serialize, Deserialize)]
pub enum GlobalACLStrings {
    AllowAll,
    DenyAll,
    AllowLocal,
    DenyLocal,
    AllowForwardFrom,
    DenyForwardFrom,
    AllowForwardTo,
    DenyForwardTo,
    AllowInbound,
    DenyInbound,
    AllowOutbound,
    DenyOutbound,
    AllowCreateInvites,
    DenyCreateInvites,
    AllowSelfAdmin,
    DenySelfAdmin,
}

impl Display for GlobalACLStrings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            GlobalACLStrings::AllowAll => write!(f, "allow_all"),
            GlobalACLStrings::DenyAll => write!(f, "deny_all"),
            GlobalACLStrings::AllowLocal => write!(f, "allow_local"),
            GlobalACLStrings::DenyLocal => write!(f, "deny_local"),
            GlobalACLStrings::AllowForwardFrom => write!(f, "allow_forward_from"),
            GlobalACLStrings::DenyForwardFrom => write!(f, "deny_forward_from"),
            GlobalACLStrings::AllowForwardTo => write!(f, "allow_forward_to"),
            GlobalACLStrings::DenyForwardTo => write!(f, "deny_forward_to"),
            GlobalACLStrings::AllowInbound => write!(f, "allow_inbound"),
            GlobalACLStrings::DenyInbound => write!(f, "deny_inbound"),
            GlobalACLStrings::AllowOutbound => write!(f, "allow_outbound"),
            GlobalACLStrings::DenyOutbound => write!(f, "deny_outbound"),
            GlobalACLStrings::AllowCreateInvites => write!(f, "allow_create_invites"),
            GlobalACLStrings::DenyCreateInvites => write!(f, "deny_create_invites"),
            GlobalACLStrings::AllowSelfAdmin => write!(f, "allow_self_admin"),
            GlobalACLStrings::DenySelfAdmin => write!(f, "deny_self_admin"),
        }
    }
}

/// What ACL logic mode is the mediator running in?
/// - ExplicitAllow - no one can connect, unless explicitly allowed
/// - ExplicitDeny - everyone can connect, unless explicitly denied
#[derive(Clone, Deserialize, PartialEq, Serialize)]
pub enum GlobalACLMode {
    ExplicitAllow,
    ExplicitDeny,
}

impl fmt::Debug for GlobalACLMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            GlobalACLMode::ExplicitAllow => write!(f, "explicit_allow"),
            GlobalACLMode::ExplicitDeny => write!(f, "explicit_deny"),
        }
    }
}

impl fmt::Display for GlobalACLMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            GlobalACLMode::ExplicitAllow => write!(f, "explicit_allow"),
            GlobalACLMode::ExplicitDeny => write!(f, "explicit_deny"),
        }
    }
}

impl Mediator {
    /// Parses the response from the mediator for Global ACL Get
    fn _parse_global_acls_get_response(
        &self,
        message: &Message,
    ) -> Result<MediatorGlobalACLResponse, ATMError> {
        serde_json::from_value(message.body.clone()).map_err(|err| {
            ATMError::MsgReceiveError(format!(
                "Mediator Gloabl ACL get response could not be parsed. Reason: {}",
                err
            ))
        })
    }

    /// Get the Global ACL's set for a list of DIDs
    pub async fn global_acls_get(
        &self,
        atm: &ATM,
        profile: &Arc<Profile>,
        dids: &Vec<String>,
    ) -> Result<MediatorGlobalACLResponse, ATMError> {
        let _span = span!(Level::DEBUG, "global_acls_get");

        async move {
            debug!("Requesting Global ACLs for DIDs: {:?}", dids);

            let (profile_did, mediator_did) = profile.dids()?;

            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let msg = Message::build(
                Uuid::new_v4().into(),
                "https://didcomm.org/mediator/1.0/global-acl-management".to_owned(),
                json!({"acl_get": dids}),
            )
            .to(mediator_did.into())
            .from(profile_did.into())
            .created_time(now)
            .expires_time(now + 10)
            .finalize();

            let msg_id = msg.id.clone();

            // Pack the message
            let (msg, _) = msg
                .pack_encrypted(
                    mediator_did,
                    Some(profile_did),
                    Some(profile_did),
                    &atm.inner.did_resolver,
                    &atm.inner.secrets_resolver,
                    &PackEncryptedOptions::default(),
                )
                .await
                .map_err(|e| ATMError::MsgSendError(format!("Error packing message: {}", e)))?;

            if let SendMessageResponse::Message(message) =
                atm.send_message(profile, &msg, &msg_id, true).await?
            {
                self._parse_global_acls_get_response(&message)
            } else {
                Err(ATMError::MsgReceiveError(
                    "No response from mediator".to_owned(),
                ))
            }
        }
        .instrument(_span)
        .await
    }
}
