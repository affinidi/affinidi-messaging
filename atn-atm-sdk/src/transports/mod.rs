pub mod http;
pub mod websockets;

pub struct SendMessageResponse {
    pub message_digest: String,
    pub bytes_sent: u32,
}
