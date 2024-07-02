pub mod http;
pub mod websockets;

#[derive(Debug)]
pub struct SendMessageResponse<T> {
    pub message_digest: String,
    pub bytes_sent: u32,
    pub http_response: Option<T>,
}
