use affinidi_did_resolver_cache_sdk::{config::ClientConfigBuilder, DIDCacheClient};
use affinidi_messaging_didcomm::{
    envelope::MetaEnvelope, secrets::SecretsResolver, AttachmentData, Message,
    PackEncryptedOptions, UnpackMetadata, UnpackOptions,
};
use affinidi_messaging_mediator::{resolvers::affinidi_secrets::AffinidiSecrets, server::start};
use affinidi_messaging_sdk::{
    config::Config,
    conversions::secret_from_str,
    errors::ATMError,
    messages::{
        fetch::FetchOptions, sending::InboundMessageResponse, AuthenticationChallenge,
        AuthorizationResponse, DeleteMessageRequest, DeleteMessageResponse, Folder,
        GenericDataStruct, GetMessagesRequest, GetMessagesResponse, MessageList,
        MessageListElement, SuccessResponse,
    },
    protocols::message_pickup::MessagePickupStatusReply,
    transports::SendMessageResponse,
};
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use common::{BOB_DID, BOB_E1, BOB_V1, MEDIATOR_API, MY_DID, MY_E1, MY_V1};
use core::panic;
use message_builders::{
    build_delivery_request_message, build_forward_request_message, build_message_received_message,
    build_ping_message, build_status_request_message, create_auth_challenge_response,
};
use reqwest::{Certificate, Client, ClientBuilder};
use serde_json::json;
use sha256::digest;
use std::time::Duration;
use tokio::time::sleep;

mod common;
mod message_builders;

#[tokio::test]
async fn test_mediator_server() {
    _start_mediator_server().await;

    // Allow some time for the server to start
    sleep(Duration::from_millis(1000)).await;

    let config = Config::builder()
        .with_ssl_certificates(&mut vec![
            "../affinidi-messaging-mediator/conf/keys/client.chain".into(),
        ])
        .build()
        .unwrap();

    let did_resolver = DIDCacheClient::new(ClientConfigBuilder::default().build())
        .await
        .unwrap();
    let my_secrets_resolver = AffinidiSecrets::new(vec![
        secret_from_str(&format!("{}#key-1", MY_DID), &MY_V1),
        secret_from_str(&format!("{}#key-2", MY_DID), &MY_E1),
    ]);
    let bob_secrets_resolver = AffinidiSecrets::new(vec![
        secret_from_str(&format!("{}#key-1", BOB_DID), &BOB_V1),
        secret_from_str(&format!("{}#key-2", BOB_DID), &BOB_E1),
    ]);

    let client = init_client(config.clone());

    let mediator_did = _well_known(client.clone()).await;

    // Start Authentication
    let my_authentication_challenge = _authenticate_challenge(client.clone(), MY_DID).await;
    let bob_authentication_challenge = _authenticate_challenge(client.clone(), BOB_DID).await;
    println!("Auth ch: {:#?}", my_authentication_challenge);
    println!("Auth ch: {:#?}", bob_authentication_challenge);
    // /authenticate/challenge
    let my_auth_response_msg =
        create_auth_challenge_response(&my_authentication_challenge, MY_DID, &mediator_did);

    let bob_auth_response_msg =
        create_auth_challenge_response(&bob_authentication_challenge, BOB_DID, &mediator_did);

    // /authenticate
    let my_authentication_response = _authenticate(
        client.clone(),
        my_auth_response_msg,
        MY_DID,
        &mediator_did,
        &did_resolver,
        &my_secrets_resolver,
    )
    .await;
    let bob_authentication_response = _authenticate(
        client.clone(),
        bob_auth_response_msg,
        BOB_DID,
        &mediator_did,
        &did_resolver,
        &bob_secrets_resolver,
    )
    .await;

    assert!(!my_authentication_response.access_token.is_empty());
    assert!(!my_authentication_response.refresh_token.is_empty());
    assert!(!bob_authentication_response.access_token.is_empty());
    assert!(!bob_authentication_response.refresh_token.is_empty());

    // POST /inbound
    // MessageType=TrustPing
    // Send signed ping and expecting response
    let (signed_ping_msg, mut signed_ping_msg_info) = build_ping_message(
        &mediator_did,
        MY_DID.into(),
        true,
        true,
        &did_resolver,
        &my_secrets_resolver,
    )
    .await;

    let signed_ping_res: SendMessageResponse<InboundMessageResponse> = _send_inbound_message(
        client.clone(),
        my_authentication_response.clone(),
        &signed_ping_msg,
        true,
        200,
    )
    .await;

    signed_ping_msg_info.response =
        if let SendMessageResponse::RestAPI(Some(InboundMessageResponse::Stored(m))) =
            signed_ping_res
        {
            if let Some((_, msg_id)) = m.messages.first() {
                Some(msg_id.to_owned())
            } else {
                None
            }
        } else {
            None
        };

    let pong_msg_id = signed_ping_msg_info.response.unwrap();
    assert!(!pong_msg_id.is_empty());

    // Send anonymous ping
    let (anon_ping_msg, _) = build_ping_message(
        &mediator_did,
        MY_DID.into(),
        false,
        false,
        &did_resolver,
        &my_secrets_resolver,
    )
    .await;
    let _anon_ping_res: SendMessageResponse<InboundMessageResponse> = _send_inbound_message(
        client.clone(),
        my_authentication_response.clone(),
        &anon_ping_msg,
        false,
        500,
    )
    .await;

    // MessageType=MessagePickupStatusRequest
    let status_request_msg = build_status_request_message(
        &mediator_did,
        MY_DID.into(),
        &did_resolver,
        &my_secrets_resolver,
    )
    .await;
    let status_reply: SendMessageResponse<InboundMessageResponse> = _send_inbound_message(
        client.clone(),
        my_authentication_response.clone(),
        &status_request_msg,
        false,
        200,
    )
    .await;
    _validate_status_reply(status_reply, &did_resolver, &my_secrets_resolver).await;

    // MessageType=MessagePickupDeliveryRequest
    let delivery_request_msg = build_delivery_request_message(
        &mediator_did,
        MY_DID.into(),
        &did_resolver,
        &my_secrets_resolver,
    )
    .await;
    let message_delivery: SendMessageResponse<InboundMessageResponse> = _send_inbound_message(
        client.clone(),
        my_authentication_response.clone(),
        &delivery_request_msg,
        true,
        200,
    )
    .await;
    let message_received_ids = _validate_message_delivery(
        message_delivery,
        &did_resolver,
        &my_secrets_resolver,
        &pong_msg_id,
    )
    .await;

    // MessageType=MessagePickupMessagesReceived
    let message_received_msg = build_message_received_message(
        &mediator_did,
        MY_DID.into(),
        &did_resolver,
        &my_secrets_resolver,
        message_received_ids.clone(),
    )
    .await;
    let message_received_status_reply: SendMessageResponse<InboundMessageResponse> =
        _send_inbound_message(
            client.clone(),
            my_authentication_response.clone(),
            &message_received_msg,
            true,
            200,
        )
        .await;
    _validate_message_received_status_reply(
        message_received_status_reply,
        &did_resolver,
        &my_secrets_resolver,
    )
    .await;

    // MessageType=ForwardRequest
    let forward_request_msg = build_forward_request_message(
        &mediator_did,
        MY_DID.into(),
        BOB_DID.into(),
        &did_resolver,
        &bob_secrets_resolver,
    )
    .await;

    let forward_request_response: SendMessageResponse<InboundMessageResponse> =
        _send_inbound_message(
            client.clone(),
            my_authentication_response.clone(),
            &forward_request_msg,
            true,
            200,
        )
        .await;

    let forwarded_msg_id = _validate_forward_request_response(forward_request_response).await;

    // /outbound
    // delete messages: FALSE
    let get_message_no_delete_request = GetMessagesRequest {
        message_ids: vec![forwarded_msg_id.clone()],
        delete: false,
    };
    let msg_list = _outbound_message(
        client.clone(),
        &get_message_no_delete_request,
        my_authentication_response.clone(),
        200,
        false,
    )
    .await;

    _validate_get_message_response(msg_list, MY_DID, &did_resolver, &my_secrets_resolver).await;

    // delete messages: TRUE
    let get_message_delete_request = GetMessagesRequest {
        message_ids: vec![forwarded_msg_id.clone()],
        delete: true,
    };
    let msg_list = _outbound_message(
        client.clone(),
        &get_message_delete_request,
        my_authentication_response.clone(),
        200,
        false,
    )
    .await;

    _validate_get_message_response(msg_list, MY_DID, &did_resolver, &my_secrets_resolver).await;

    // get message should return not found
    let _msg_list = _outbound_message(
        client.clone(),
        &get_message_delete_request,
        my_authentication_response.clone(),
        200,
        true,
    )
    .await;

    // Sending messages to list/fetch
    for _ in 0..3 {
        let (signed_ping_msg, _) = build_ping_message(
            &mediator_did,
            MY_DID.into(),
            true,
            true,
            &did_resolver,
            &my_secrets_resolver,
        )
        .await;

        let _: SendMessageResponse<InboundMessageResponse> = _send_inbound_message(
            client.clone(),
            my_authentication_response.clone(),
            &signed_ping_msg,
            true,
            200,
        )
        .await;
    }

    // /list/:did_hash/:folder
    // /list/:did_hash/Inbox
    let msgs_list = list_messages(
        client.clone(),
        my_authentication_response.clone(),
        200,
        MY_DID,
        Folder::Inbox,
    )
    .await;
    _validate_list_messages(msgs_list, &mediator_did);

    // /list/:did_hash/Outbox
    let msgs_list = list_messages(
        client.clone(),
        my_authentication_response.clone(),
        200,
        MY_DID,
        Folder::Outbox,
    )
    .await;
    assert_eq!(msgs_list.len(), 0);

    // /fetch
    let messages = fetch_messages(
        client.clone(),
        my_authentication_response.clone(),
        200,
        &FetchOptions {
            limit: 10,
            start_id: None,
            delete_policy: affinidi_messaging_sdk::messages::FetchDeletePolicy::DoNotDelete,
        },
    )
    .await;
    assert_eq!(messages.success.len(), 3);

    let msg_ids: Vec<String> = messages
        .success
        .iter()
        .map(|msg| msg.msg_id.clone())
        .collect();

    let deleted_msgs = _delete_messages(
        client.clone(),
        my_authentication_response.clone(),
        200,
        &DeleteMessageRequest {
            message_ids: msg_ids,
        },
    )
    .await;
    assert_eq!(deleted_msgs.success.len(), 3);
}

async fn _start_mediator_server() {
    tokio::spawn(async move { start().await });
    println!("Server running");
}

fn init_client(config: Config<'_>) -> Client {
    // Set up the HTTPS client
    let mut client = ClientBuilder::new()
        .use_rustls_tls()
        .https_only(true)
        .user_agent("Affinidi Trusted Messaging");

    for cert in config.get_ssl_certificates() {
        client =
            client.add_root_certificate(Certificate::from_der(cert.to_vec().as_slice()).unwrap());
    }

    let client = match client.build() {
        Ok(client) => client,
        Err(e) => {
            assert!(false, "{:?}", e);
            panic!();
        }
    };
    client
}

async fn _well_known(client: Client) -> String {
    let well_known_did_atm_api = format!("{}/.well-known/did", MEDIATOR_API);

    let res = client
        .get(well_known_did_atm_api)
        .header("Content-Type", "application/json")
        .send()
        .await
        .unwrap();

    let status = res.status();
    assert_eq!(status, 200);
    println!("API response: status({})", status);
    let body = res.text().await.unwrap();

    let body = serde_json::from_str::<SuccessResponse<String>>(&body)
        .ok()
        .unwrap();
    let did = if let Some(did) = body.data {
        did
    } else {
        panic!("Not able to fetch mediator did");
    };
    assert!(!did.is_empty());

    did
}

async fn _authenticate_challenge(client: Client, did: &str) -> AuthenticationChallenge {
    let res = client
        .post(format!("{}/authenticate/challenge", MEDIATOR_API))
        .header("Content-Type", "application/json")
        .body(format!("{{\"did\": \"{}\"}}", did).to_string())
        .send()
        .await
        .unwrap();

    let status = res.status();
    assert_eq!(status, 200);

    let body = res.text().await.unwrap();

    if !status.is_success() {
        println!("Failed to get authentication challenge. Body: {:?}", body);
        assert!(
            false,
            "Failed to get authentication challenge. Body: {:?}",
            body
        );
    }
    let body = serde_json::from_str::<SuccessResponse<AuthenticationChallenge>>(&body)
        .ok()
        .unwrap();

    let challenge = if let Some(challenge) = body.data {
        challenge
    } else {
        panic!("No challenge received from ATM");
    };
    assert!(!challenge.challenge.is_empty());
    assert!(!challenge.session_id.is_empty());

    challenge
}

async fn _authenticate<'sr>(
    client: Client,
    auth_response: Message,
    my_did: &str,
    atm_did: &str,
    did_resolver: &DIDCacheClient,
    secrets_resolver: &'sr (dyn SecretsResolver + 'sr + Sync),
) -> AuthorizationResponse {
    let (auth_msg, _) = auth_response
        .pack_encrypted(
            atm_did,
            Some(my_did),
            Some(my_did),
            did_resolver,
            secrets_resolver,
            &PackEncryptedOptions::default(),
        )
        .await
        .map_err(|e| {
            ATMError::MsgSendError(format!(
                "Couldn't pack authentication response message: {:?}",
                e
            ))
        })
        .unwrap();

    let res = client
        .post(format!("{}/authenticate", MEDIATOR_API))
        .header("Content-Type", "application/json")
        .body(auth_msg)
        .send()
        .await
        .map_err(|e| {
            ATMError::TransportError(format!("Could not post authentication response: {:?}", e))
        })
        .unwrap();

    let status = res.status();
    println!("Authentication response: status({})", status);

    let body = res.text().await.unwrap();

    assert!(status.is_success());

    if !status.is_success() {
        println!("Failed to get authentication response. Body: {:?}", body);
        panic!("Failed to get authentication response");
    }
    let body = serde_json::from_str::<SuccessResponse<AuthorizationResponse>>(&body).unwrap();

    if let Some(tokens) = body.data {
        return tokens.clone();
    } else {
        panic!("No tokens received from ATM");
    }
}

async fn _validate_status_reply<S>(
    status_reply: SendMessageResponse<InboundMessageResponse>,
    did_resolver: &DIDCacheClient,
    secrets_resolver: &S,
) where
    S: SecretsResolver + Send,
{
    if let SendMessageResponse::RestAPI(Some(InboundMessageResponse::Ephemeral(message))) =
        status_reply
    {
        let (message, _) = Message::unpack_string(
            &message,
            &did_resolver,
            secrets_resolver,
            &UnpackOptions::default(),
        )
        .await
        .unwrap();
        let status: MessagePickupStatusReply =
            serde_json::from_value(message.body.clone()).unwrap();
        assert!(!status.live_delivery);
        assert!(status.longest_waited_seconds.unwrap() > 0);
        assert!(status.message_count == 1);
        assert!(status.recipient_did == MY_DID);
        assert!(status.total_bytes > 0);
    }
}

async fn _handle_delivery<S>(
    message: &Message,
    did_resolver: &DIDCacheClient,
    secrets_resolver: &S,
) -> Vec<(Message, UnpackMetadata)>
where
    S: SecretsResolver + Send,
{
    let mut response: Vec<(Message, UnpackMetadata)> = Vec::new();

    if let Some(attachments) = &message.attachments {
        for attachment in attachments {
            match &attachment.data {
                AttachmentData::Base64 { value } => {
                    let decoded = match BASE64_URL_SAFE_NO_PAD.decode(value.base64.clone()) {
                        Ok(decoded) => match String::from_utf8(decoded) {
                            Ok(decoded) => decoded,
                            Err(e) => {
                                assert!(false, "{:?}", e);
                                "".into()
                            }
                        },
                        Err(e) => {
                            assert!(false, "{:?}", e);
                            continue;
                        }
                    };
                    let mut envelope =
                        match MetaEnvelope::new(&decoded, &did_resolver, secrets_resolver).await {
                            Ok(envelope) => envelope,
                            Err(e) => {
                                assert!(false, "{:?}", e);
                                continue;
                            }
                        };

                    match Message::unpack(
                        &mut envelope,
                        did_resolver,
                        secrets_resolver,
                        &UnpackOptions::default(),
                    )
                    .await
                    {
                        Ok((mut m, u)) => {
                            if let Some(attachment_id) = &attachment.id {
                                m.id = attachment_id.to_string();
                            }
                            response.push((m, u))
                        }
                        Err(e) => {
                            assert!(false, "{:?}", e);
                            continue;
                        }
                    };
                }
                _ => {
                    assert!(false);
                    continue;
                }
            };
        }
    }

    response
}

async fn _validate_message_delivery<S>(
    message_delivery: SendMessageResponse<InboundMessageResponse>,
    did_resolver: &DIDCacheClient,
    secrets_resolver: &S,
    pong_msg_id: &str,
) -> Vec<String>
where
    S: SecretsResolver + Send,
{
    if let SendMessageResponse::RestAPI(Some(InboundMessageResponse::Ephemeral(message))) =
        message_delivery
    {
        let (message, _) = Message::unpack_string(
            &message,
            &did_resolver,
            secrets_resolver,
            &UnpackOptions::default(),
        )
        .await
        .unwrap();

        let messages = _handle_delivery(&message, did_resolver, secrets_resolver).await;
        let mut to_delete_ids: Vec<String> = Vec::new();

        assert_eq!(messages.first().unwrap().0.id, pong_msg_id);

        for (message, _) in messages {
            to_delete_ids.push(message.id.clone());
        }
        to_delete_ids
    } else {
        vec![]
    }
}

async fn _validate_message_received_status_reply<S>(
    status_reply: SendMessageResponse<InboundMessageResponse>,
    did_resolver: &DIDCacheClient,
    secrets_resolver: &S,
) where
    S: SecretsResolver + Send,
{
    if let SendMessageResponse::RestAPI(Some(InboundMessageResponse::Ephemeral(message))) =
        status_reply
    {
        let (message, _) = Message::unpack_string(
            &message,
            &did_resolver,
            secrets_resolver,
            &UnpackOptions::default(),
        )
        .await
        .unwrap();
        let status: MessagePickupStatusReply =
            serde_json::from_value(message.body.clone()).unwrap();

        assert!(!status.live_delivery);
        assert!(status.longest_waited_seconds.is_none());
        assert!(status.message_count == 0);
        assert!(status.recipient_did == MY_DID);
        assert!(status.total_bytes == 0);
    }
}

async fn _validate_forward_request_response(
    forward_request_response: SendMessageResponse<InboundMessageResponse>,
) -> String {
    let msg_id = if let SendMessageResponse::RestAPI(Some(InboundMessageResponse::Stored(m))) =
        forward_request_response
    {
        if let Some((_, msg_id)) = m.messages.first() {
            Some(msg_id.to_owned())
        } else {
            None
        }
    } else {
        None
    };

    assert!(!msg_id.is_none());

    msg_id.unwrap()
}

async fn _validate_get_message_response<S>(
    list: GetMessagesResponse,
    my_did: &str,
    did_resolver: &DIDCacheClient,
    secrets_resolver: &S,
) where
    S: SecretsResolver + Send,
{
    for msg in list.success {
        assert_eq!(msg.to_address.unwrap(), digest(my_did));
        let _ = Message::unpack_string(
            &msg.msg.unwrap(),
            did_resolver,
            secrets_resolver,
            &UnpackOptions::default(),
        )
        .await
        .unwrap();
        println!("Msg id: {}", msg.msg_id);
    }
}

async fn _send_inbound_message<T>(
    client: Client,
    tokens: AuthorizationResponse,
    message: &str,
    return_response: bool,
    expected_status_code: u16,
) -> SendMessageResponse<T>
where
    T: GenericDataStruct,
{
    let msg = message.to_owned();

    let res = client
        .post(format!("{}/inbound", MEDIATOR_API))
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", tokens.access_token))
        .body(msg)
        .send()
        .await
        .unwrap();

    let status = res.status();
    println!("API response: status({})", status);
    assert_eq!(status, expected_status_code);

    let body = res.text().await.unwrap();

    let http_response: Option<T> = if return_response {
        let r: SuccessResponse<T> = serde_json::from_str(&body).unwrap();
        r.data
    } else {
        None
    };

    SendMessageResponse::RestAPI(http_response)
}

async fn _outbound_message(
    client: Client,
    messages: &GetMessagesRequest,
    tokens: AuthorizationResponse,
    expected_status_code: u16,
    expecting_get_errors: bool,
) -> GetMessagesResponse {
    let body = serde_json::to_string(messages)
        .map_err(|e| {
            ATMError::TransportError(format!("Could not serialize get message request: {:?}", e))
        })
        .unwrap();

    let res = client
        .post(format!("{}/outbound", MEDIATOR_API))
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", tokens.access_token))
        .body(body)
        .send()
        .await
        .map_err(|e| {
            ATMError::TransportError(format!("Could not send get_messages request: {:?}", e))
        })
        .unwrap();

    let status = res.status();
    println!("API response: status({})", status);
    assert_eq!(status, expected_status_code);
    let body = res
        .text()
        .await
        .map_err(|e| ATMError::TransportError(format!("Couldn't get body: {:?}", e)))
        .unwrap();

    let body = serde_json::from_str::<SuccessResponse<GetMessagesResponse>>(&body)
        .ok()
        .unwrap();

    let list = if let Some(list) = body.data {
        list
    } else {
        panic!("No messages found")
    };

    if expecting_get_errors {
        assert!(!list.get_errors.is_empty())
    } else {
        assert!(list.get_errors.is_empty())
    }

    if !list.get_errors.is_empty() {
        for (msg, err) in &list.get_errors {
            println!("failed get: msg({}) error({})", msg, err);
        }
    }
    if !list.delete_errors.is_empty() {
        for (msg, err) in &list.delete_errors {
            println!("failed delete: msg({}) error({})", msg, err);
        }
    }
    list
}

fn _validate_list_messages(list: Vec<MessageListElement>, mediator_did: &str) {
    assert_eq!(list.len(), 3);

    for msg in list {
        assert_eq!(msg.from_address.unwrap(), mediator_did);
    }
}

async fn list_messages(
    client: Client,
    tokens: AuthorizationResponse,
    expected_status_code: u16,
    my_did: &str,
    folder: Folder,
) -> Vec<MessageListElement> {
    let res = client
        .get(format!(
            "{}/list/{}/{}",
            MEDIATOR_API,
            digest(my_did),
            folder,
        ))
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", tokens.access_token))
        .send()
        .await
        .map_err(|e| {
            ATMError::TransportError(format!("Could not send list_messages request: {:?}", e))
        })
        .unwrap();

    let status = res.status();
    println!("API response: status({})", status);
    assert_eq!(status, expected_status_code);

    let body = res
        .text()
        .await
        .map_err(|e| ATMError::TransportError(format!("Couldn't get body: {:?}", e)))
        .unwrap();

    let body = serde_json::from_str::<SuccessResponse<MessageList>>(&body)
        .ok()
        .unwrap();

    let list = if let Some(list) = body.data {
        list
    } else {
        panic!("No messages found");
    };

    list
}

async fn fetch_messages(
    client: Client,
    tokens: AuthorizationResponse,
    expected_status_code: u16,
    options: &FetchOptions,
) -> GetMessagesResponse {
    let body = serde_json::to_string(options)
        .map_err(|e| {
            ATMError::TransportError(format!(
                "Could not serialize fetch_message() options: {:?}",
                e
            ))
        })
        .unwrap();

    let res = client
        .post(format!("{}/fetch", MEDIATOR_API))
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", tokens.access_token))
        .body(body)
        .send()
        .await
        .map_err(|e| {
            ATMError::TransportError(format!("Could not send list_messages request: {:?}", e))
        })
        .unwrap();

    let status = res.status();
    println!("API response: status({})", status);
    assert_eq!(status, expected_status_code);

    let body = res
        .text()
        .await
        .map_err(|e| ATMError::TransportError(format!("Couldn't get body: {:?}", e)))
        .unwrap();

    let body = serde_json::from_str::<SuccessResponse<GetMessagesResponse>>(&body)
        .ok()
        .unwrap();

    let list = if let Some(list) = body.data {
        list
    } else {
        panic!("No messages found");
    };
    list
}

async fn _delete_messages(
    client: Client,
    tokens: AuthorizationResponse,
    expected_status_code: u16,
    messages: &DeleteMessageRequest,
) -> DeleteMessageResponse {
    let msg = serde_json::to_string(messages)
        .map_err(|e| {
            ATMError::TransportError(format!(
                "Could not serialize delete message request: {:?}",
                e
            ))
        })
        .unwrap();

    let res = client
        .delete(format!("{}/delete", MEDIATOR_API))
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", tokens.access_token))
        .body(msg)
        .send()
        .await
        .map_err(|e| {
            ATMError::TransportError(format!("Could not send delete_messages request: {:?}", e))
        })
        .unwrap();

    let status = res.status();
    println!("API response: status({})", status);
    assert_eq!(status, expected_status_code);

    let body = res
        .text()
        .await
        .map_err(|e| ATMError::TransportError(format!("Couldn't get body: {:?}", e)))
        .unwrap();

    let body = serde_json::from_str::<SuccessResponse<DeleteMessageResponse>>(&body)
        .ok()
        .unwrap();

    let list = if let Some(list) = body.data {
        list
    } else {
        panic!("No messages found");
    };

    if !list.errors.is_empty() {
        for (msg, err) in &list.errors {
            println!("failed: msg({}) error({})", msg, err);
        }
        panic!("Failed to delete above messages")
    }

    list
}
