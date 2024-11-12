use std::{sync::Arc, time::Duration};

use affinidi_messaging_didcomm::Message;
use tokio::sync::RwLock;
use tracing::debug;
use websockets::ws_connection::WsConnectionCommands;

use crate::{
    errors::ATMError,
    messages::{
        known::MessageType, sending::InboundMessageResponse, GenericDataStruct, SuccessResponse,
    },
    profiles::Profile,
    protocols::message_pickup::MessagePickup,
    ATM,
};

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
#[derive(Debug)]
pub enum SendMessageResponse<T> {
    RestAPI(Option<T>),
    WebSocket(WebSocketSendResponse),
}

impl<T> SendMessageResponse<T> {
    pub fn get_http_response(&self) -> Option<&T> {
        match self {
            SendMessageResponse::RestAPI(Some(response)) => Some(response),
            SendMessageResponse::WebSocket(_) => None,
            _ => None,
        }
    }
}

impl ATM {
    pub async fn send_message<T>(
        &self,
        profile: &Arc<RwLock<Profile>>,
        message: &str,
        msg_id: &str,
    ) -> Result<Message, ATMError> {
        let _profile = &profile.read().await;

        let Some(mediator) = &_profile.mediator else {
            return Err(ATMError::ConfigError(
                "No Mediator is configured for this Profile".to_string(),
            ));
        };

        let message_received = if mediator.ws_connected {
            // Send to the WS_Connection task for this profile

            if let Some(channel) = &mediator.ws_channel_tx {
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

            debug!("Profile ({}): WebSocket Channel notified", _profile.alias);

            let response = MessagePickup::default()
                .live_stream_get(self, profile, msg_id, Duration::from_secs(10))
                .await?;

            if let Some((message, _)) = response {
                message
            } else {
                return Err(ATMError::MsgSendError("No response from API".into()));
            }
        } else {
            // Send HTTP message
            let a = self
                .send_didcomm_message::<InboundMessageResponse>(profile, message, true)
                .await?;

            debug!("Response: {:?}", a);

            // Unpack the response
            if let SendMessageResponse::RestAPI(Some(InboundMessageResponse::Ephemeral(message))) =
                a
            {
                let (message, _) = self.unpack(&message).await?;
                message
            } else {
                return Err(ATMError::MsgSendError("No response from API".into()));
            }
        };

        let type_ = message_received.type_.parse::<MessageType>()?;
        if let MessageType::ProblemReport = type_ {
            Err(ATMError::from_problem_report(&message_received))
        } else {
            Ok(message_received)
        }
    }

    /// send_didcomm_message
    /// - msg: Packed DIDComm message that we want to send
    /// - return_response: Whether to return the response from the API
    pub async fn send_didcomm_message<T>(
        &self,
        profile: &Arc<RwLock<Profile>>,
        message: &str,
        return_response: bool,
    ) -> Result<SendMessageResponse<T>, ATMError>
    where
        T: GenericDataStruct,
    {
        let _profile = &profile.read().await;
        let Some(mediator_url) = _profile.get_mediator_rest_endpoint() else {
            return Err(ATMError::MsgSendError(format!(
                "Profile ({}): Missing a valid mediator URL",
                _profile.alias
            )));
        };

        let tokens = profile.write().await.authenticate(&self.inner).await?;

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
        let http_response: Option<T> = if return_response {
            let r: SuccessResponse<T> = serde_json::from_str(&body).map_err(|e| {
                ATMError::TransportError(format!("Couldn't parse response: {:?}", e))
            })?;
            r.data
        } else {
            None
        };

        Ok(SendMessageResponse::RestAPI(http_response))
    }
}
