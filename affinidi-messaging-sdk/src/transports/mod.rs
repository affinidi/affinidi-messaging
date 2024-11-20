use crate::{
    errors::ATMError,
    messages::{known::MessageType, GenericDataStruct, GetMessagesRequest},
    profiles::Profile,
    protocols::message_pickup::MessagePickup,
    ATM,
};
use affinidi_messaging_didcomm::Message;
use serde_json::Value;
use sha256::digest;
use std::{sync::Arc, time::Duration};
use tracing::debug;
use websockets::ws_connection::WsConnectionCommands;

pub mod websockets;

/// WebSocketSendResponse is the response from sending a message over a WebSocket connection
/// message_digest is sha256 digest of the message sent
/// bytes_sent is the number of bytes sent
/// message_id is the id of the message sent
#[derive(Debug)]
pub struct WebSocketSendResponse {
    pub message_digest: String,
    pub bytes_sent: u32,
    pub message_id: String,
}

/// SendMessageResponse is the response from sending a message
/// Allows for returning the response from the API or the WebSocket
/// - RestAPI: The response from the API (JSON Value response)
/// - Message: The response from the WebSocket (DIDComm Message)
/// - EmptyResponse: No response was received or expected
#[derive(Debug)]
pub enum SendMessageResponse {
    RestAPI(Value),
    Message(Message),
    EmptyResponse,
}

impl SendMessageResponse {
    pub fn get_http_response<T>(&self) -> Option<T>
    where
        T: GenericDataStruct,
    {
        match self {
            SendMessageResponse::RestAPI(value) => serde_json::from_value(value.to_owned()).ok(),
            SendMessageResponse::Message(_) => None,
            SendMessageResponse::EmptyResponse => None,
        }
    }
}

impl ATM {
    /// Send a message to a mediator based on a given profile
    /// - profile: The profile to connect to the mediator with
    /// - message: The message to send (already packed as a DIDComm message)
    /// - msg_id: The ID of the message (used for message response pickup)
    /// - wait_for_response: Whether to wait for a message response from the mediator
    ///
    /// Returns: If wait_for_response is true, the response message from the mediator
    ///          Else Ok(None) - Message sent Successfully
    ///          Else Err - Error sending message    
    ///
    pub async fn send_message(
        &self,
        profile: &Arc<Profile>,
        message: &str,
        msg_id: &str,
        wait_for_response: bool,
    ) -> Result<SendMessageResponse, ATMError> {
        let Some(mediator) = &*profile.inner.mediator else {
            return Err(ATMError::ConfigError(
                "No Mediator is configured for this Profile".to_string(),
            ));
        };

        if mediator
            .ws_connected
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            // Send to the WS_Connection task for this profile
            debug!(
                "Profile ({}): Sending message to WebSocket Connection Handler",
                profile.inner.alias
            );

            if let Some(channel) = &*mediator.ws_channel_tx.lock().await {
                channel
                    .send(WsConnectionCommands::Send(message.to_owned()))
                    .await
                    .map_err(|err| {
                        ATMError::TransportError(format!(
                            "Could not send websocket message: {:?}",
                            err
                        ))
                    })?;
            }

            debug!(
                "Profile ({}): WebSocket Channel notified",
                profile.inner.alias
            );

            if wait_for_response {
                let response = MessagePickup::default()
                    .live_stream_get(self, profile, true, msg_id, Duration::from_secs(10))
                    .await?;

                if let Some((message, _)) = response {
                    let type_ = message.type_.parse::<MessageType>()?;
                    if let MessageType::ProblemReport = type_ {
                        Err(ATMError::from_problem_report(&message))
                    } else {
                        Ok(SendMessageResponse::Message(message))
                    }
                } else {
                    Err(ATMError::MsgSendError("No response from API".into()))
                }
            } else {
                Ok(SendMessageResponse::EmptyResponse)
            }
        } else {
            debug!("Profile ({}): Sending message to API", profile.inner.alias);
            // Send HTTP message
            let a = self.send_didcomm_message(profile, message, true).await?;

            debug!("Response: {:#?}", a);

            if wait_for_response {
                let response = self
                    .get_messages(
                        profile,
                        &GetMessagesRequest {
                            message_ids: vec![digest(message)],
                            delete: true,
                        },
                    )
                    .await?;

                if let Some(first) = response.success.first() {
                    if let Some(msg) = &first.msg {
                        let unpack = self.unpack(msg).await?;

                        Ok(SendMessageResponse::Message(unpack.0))
                    } else {
                        Err(ATMError::MsgReceiveError(
                            "Received message response, but no actual message".into(),
                        ))
                    }
                } else {
                    Err(ATMError::MsgReceiveError(
                        "No Message retrieved from Mediator".into(),
                    ))
                }
            } else {
                Ok(a)
            }
        }
    }

    /// send_didcomm_message
    /// - msg: Packed DIDComm message that we want to send
    /// - return_response: Whether to return the response from the API
    pub(crate) async fn send_didcomm_message(
        &self,
        profile: &Arc<Profile>,
        message: &str,
        return_response: bool,
    ) -> Result<SendMessageResponse, ATMError> {
        let mediator_url = {
            let url = profile.get_mediator_rest_endpoint();
            if let Some(url) = url {
                url
            } else {
                return Err(ATMError::MsgSendError(
                    "Profile is missing a valid mediator URL".into(),
                ));
            }
        };

        let tokens = profile.authenticate(&self.inner).await?;

        let msg = message.to_owned();

        let res = self
            .inner
            .client
            .post([&mediator_url, "/inbound"].concat())
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", tokens.access_token))
            .body(msg)
            .send()
            .await
            .map_err(|e| ATMError::TransportError(format!("Could not send message: {:?}", e)))?;

        let status = res.status();
        debug!("API response: status({})", status);

        let body = res
            .text()
            .await
            .map_err(|e| ATMError::TransportError(format!("Couldn't get body: {:?}", e)))?;

        if !status.is_success() {
            return Err(ATMError::TransportError(format!(
                "API returned an error: status({}), body({})",
                status, body
            )));
        }
        debug!("body =\n{}", body);
        let http_response: Value = if return_response {
            serde_json::from_str(&body).map_err(|e| {
                ATMError::TransportError(format!("Couldn't parse response: {:?}", e))
            })?
        } else {
            Value::Null
        };

        Ok(SendMessageResponse::RestAPI(http_response))
    }
}
