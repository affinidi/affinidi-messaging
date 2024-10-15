use std::time::SystemTime;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_messaging_didcomm::{
    secrets::SecretsResolver, Attachment, Message, PackEncryptedOptions,
};
use affinidi_messaging_sdk::{
    messages::AuthenticationChallenge,
    protocols::{message_pickup::MessagePickupDeliveryRequest, trust_ping::TrustPingSent},
};
use serde_json::{json, Value};
use sha256::digest;
use uuid::Uuid;

pub fn create_auth_challenge_response(
    body: &AuthenticationChallenge,
    actor_did: &str,
    atm_did: &str,
) -> Message {
    let now = _get_time_now();

    Message::build(
        Uuid::new_v4().into(),
        "https://affinidi.com/atm/1.0/authenticate".to_owned(),
        json!(body),
    )
    .to(atm_did.to_owned())
    .from(actor_did.to_owned())
    .created_time(now)
    .expires_time(now + 60)
    .finalize()
}

pub async fn build_ping_message<'sr>(
    to_did: &str,
    actor_did: String,
    signed: bool,
    expect_response: bool,
    did_resolver: &DIDCacheClient,
    secrets_resolver: &'sr (dyn SecretsResolver + 'sr + Sync),
) -> (String, TrustPingSent) {
    let now = _get_time_now();

    let mut msg = Message::build(
        Uuid::new_v4().into(),
        "https://didcomm.org/trust-ping/2.0/ping".to_owned(),
        json!({"response_requested": expect_response}),
    )
    .to(to_did.to_owned());

    let from_did = if !signed {
        // Can support anonymous pings
        None
    } else {
        msg = msg.from(actor_did.clone());
        Some(actor_did.clone())
    };
    let msg = msg.created_time(now).expires_time(now + 300).finalize();
    let mut msg_info = TrustPingSent {
        message_id: msg.id.clone(),
        message_hash: "".to_string(),
        bytes: 0,
        response: None,
    };
    let (msg, _) = msg
        .pack_encrypted(
            to_did,
            from_did.as_deref(),
            from_did.as_deref(),
            did_resolver,
            secrets_resolver,
            &PackEncryptedOptions::default(),
        )
        .await
        .unwrap();

    msg_info.message_hash = digest(&msg).to_string();
    msg_info.bytes = msg.len() as u32;

    (msg, msg_info)
}

pub async fn build_status_request_message<'sr>(
    mediator_did: &str,
    recipient_did: String,
    did_resolver: &DIDCacheClient,
    secrets_resolver: &'sr (dyn SecretsResolver + 'sr + Sync),
) -> String {
    let mut msg = Message::build(
        Uuid::new_v4().into(),
        "https://didcomm.org/messagepickup/3.0/status-request".to_owned(),
        json!({}),
    )
    .header("return_route".into(), Value::String("all".into()));

    msg = msg.body(json!({"recipient_did": recipient_did }));

    let to_did = mediator_did;

    msg = msg.to(to_did.to_owned());

    msg = msg.from(recipient_did.clone().into());
    let now = _get_time_now();
    let msg = msg.created_time(now).expires_time(now + 300).finalize();
    let (msg, _) = msg
        .pack_encrypted(
            &to_did,
            Some(&recipient_did),
            Some(&recipient_did),
            &did_resolver,
            secrets_resolver,
            &PackEncryptedOptions::default(),
        )
        .await
        .unwrap();

    msg
}

pub async fn build_delivery_request_message<'sr>(
    mediator_did: &str,
    recipient_did: String,
    did_resolver: &DIDCacheClient,
    secrets_resolver: &'sr (dyn SecretsResolver + 'sr + Sync),
) -> String {
    let body = MessagePickupDeliveryRequest {
        recipient_did: recipient_did.clone(),
        limit: 10,
    };

    let mut msg = Message::build(
        Uuid::new_v4().into(),
        "https://didcomm.org/messagepickup/3.0/delivery-request".to_owned(),
        serde_json::to_value(body).unwrap(),
    )
    .header("return_route".into(), Value::String("all".into()));

    let to_did = mediator_did;
    msg = msg.to(to_did.to_owned());

    msg = msg.from(recipient_did.clone().to_owned());
    let now = _get_time_now();
    let msg = msg.created_time(now).expires_time(now + 300).finalize();

    // Pack the message
    let (msg, _) = msg
        .pack_encrypted(
            &to_did,
            Some(&recipient_did),
            Some(&recipient_did),
            &did_resolver,
            secrets_resolver,
            &PackEncryptedOptions::default(),
        )
        .await
        .unwrap();

    msg
}

pub async fn build_message_received_message<'sr>(
    mediator_did: &str,
    recipient_did: String,
    did_resolver: &DIDCacheClient,
    secrets_resolver: &'sr (dyn SecretsResolver + 'sr + Sync),
    to_delete_list: Vec<String>,
) -> String {
    let mut msg = Message::build(
        Uuid::new_v4().into(),
        "https://didcomm.org/messagepickup/3.0/messages-received".to_owned(),
        json!({"message_id_list": to_delete_list}),
    )
    .header("return_route".into(), Value::String("all".into()));

    let to_did = mediator_did;
    msg = msg.to(to_did.to_owned());

    msg = msg.from(recipient_did.clone().into());
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let msg = msg.created_time(now).expires_time(now + 300).finalize();

    // Pack the message
    let (msg, _) = msg
        .pack_encrypted(
            &to_did,
            Some(&recipient_did),
            Some(&recipient_did),
            &did_resolver,
            secrets_resolver,
            &PackEncryptedOptions::default(),
        )
        .await
        .unwrap();

    msg
}

pub async fn build_forward_request_message<'sr>(
    mediator_did: &str,
    recipient_did: String,
    actor_did: String,
    did_resolver: &DIDCacheClient,
    secrets_resolver: &'sr (dyn SecretsResolver + 'sr + Sync),
) -> String {
    let now = _get_time_now();

    let msg = Message::build(
        Uuid::new_v4().into(),
        "https://didcomm.org/routing/2.0/forward".to_owned(),
        json!({ "next": recipient_did }),
    )
    .to(mediator_did.to_owned())
    .from(actor_did.clone())
    .attachment(
        Attachment::json(json!({ "message": "plaintext attachment, mediator can read this" }))
            .finalize(),
    )
    .attachment(
        Attachment::base64(String::from(
            "ciphertext and iv which is encrypted by the recipient public key",
        ))
        .finalize(),
    );

    let msg = msg.created_time(now).expires_time(now + 300).finalize();

    // Pack the message
    let (msg, _) = msg
        .pack_encrypted(
            &mediator_did.to_owned(),
            Some(&actor_did.clone()),
            Some(&actor_did.clone()),
            &did_resolver,
            secrets_resolver,
            &PackEncryptedOptions::default(),
        )
        .await
        .unwrap();
    msg
}

fn _get_time_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
