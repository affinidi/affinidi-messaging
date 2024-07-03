use crate::{
    errors::ATMError,
    transports::{SendMessageResponse, WebSocketSendResponse},
    ATM,
};
use futures_util::SinkExt;
use sha256::digest;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, span, Level};

impl<'c> ATM<'c> {
    /// send_didcomm_message
    /// - msg: Packed DIDComm message that we want to send
    pub(crate) async fn ws_send_didcomm_message<T>(
        &mut self,
        message: &str,
        message_id: &str,
    ) -> Result<SendMessageResponse<T>, ATMError> {
        let _span = span!(Level::DEBUG, "send_didcomm_message",).entered();

        let ws_stream = if let Some(ws_stream) = self.ws_stream.as_mut() {
            ws_stream
        } else {
            self.start_websocket().await?
        };

        let message_digest = digest(message);

        debug!("Sending message: {:?}", message);
        ws_stream
            .send(Message::Text(message.to_owned()))
            .await
            .map_err(|e| ATMError::TransportError(format!("Could not send message: {:?}", e)))?;

        debug!("Message ({}) sent successfully", message_digest);
        Ok(SendMessageResponse::WebSocket(WebSocketSendResponse {
            message_digest,
            bytes_sent: message.len() as u32,
            message_id: message_id.into(),
        }))
    }
}
