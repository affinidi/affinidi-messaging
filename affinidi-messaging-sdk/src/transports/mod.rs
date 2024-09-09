pub mod http;
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
