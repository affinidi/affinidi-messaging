use crate::{
    errors::ATMError,
    transports::{SendMessageResponse, WebSocketSendResponse},
    websockets::ws_handler::WSCommand,
    ATM,
};
use sha256::digest;
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

        let ws_stream = if let Some(ws_stream) = &self.ws_send_stream {
            ws_stream.clone()
        } else {
            self.start_websocket_task().await?;
            self.ws_send_stream.clone().ok_or_else(|| {
                ATMError::TransportError("Could not get websocket stream".to_string())
            })?
        };

        let message_digest = digest(message);

        debug!("Sending message: {:?}", message);

        ws_stream
            .send(WSCommand::Send(message.to_owned()))
            .await
            .map_err(|err| {
                ATMError::TransportError(format!("Could not send websocket message: {:?}", err))
            })?;

        debug!("Message ({}) sent successfully", message_digest);
        Ok(SendMessageResponse::WebSocket(WebSocketSendResponse {
            message_digest,
            bytes_sent: message.len() as u32,
            message_id: message_id.into(),
        }))
    }
}
