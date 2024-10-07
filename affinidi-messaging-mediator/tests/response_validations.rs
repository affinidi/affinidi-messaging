use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_messaging_didcomm::{
    envelope::MetaEnvelope, secrets::SecretsResolver, AttachmentData, Message, UnpackMetadata,
    UnpackOptions,
};
use affinidi_messaging_sdk::{
    messages::{sending::InboundMessageResponse, GetMessagesResponse, MessageListElement},
    protocols::message_pickup::MessagePickupStatusReply,
    transports::SendMessageResponse,
};
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use sha256::digest;

pub async fn validate_status_reply<S>(
    status_reply: SendMessageResponse<InboundMessageResponse>,
    recipient_did: String,
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
        assert!(status.recipient_did == recipient_did);
        assert!(status.total_bytes > 0);
    }
}

pub async fn validate_message_delivery<S>(
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

pub async fn validate_message_received_status_reply<S>(
    status_reply: SendMessageResponse<InboundMessageResponse>,
    recipient_did: String,
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
        assert!(status.recipient_did == recipient_did);
        assert!(status.total_bytes == 0);
    }
}

pub async fn validate_forward_request_response(
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

pub async fn validate_get_message_response<S>(
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

pub fn validate_list_messages(list: Vec<MessageListElement>, mediator_did: &str) {
    assert_eq!(list.len(), 3);

    for msg in list {
        assert_eq!(msg.from_address.unwrap(), mediator_did);
    }
}
