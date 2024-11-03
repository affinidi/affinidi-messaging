use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Message {
    pub dt_received: String,
    pub id: String,
    pub message: String,
}
