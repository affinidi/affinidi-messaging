use affinidi_messaging_didcomm::{Attachment, Message};
use affinidi_messaging_sdk::{errors::ATMError, messages::sending::InboundMessageResponse};
use serde_json::json;
use std::error::Error;
use std::time::SystemTime;
use tracing::info;
use uuid::Uuid;

mod common;

use common::{bob_configuration, configure_alice_atm, ConfigureAtmResult};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let ConfigureAtmResult {
        mut atm,
        atm_did,
        actor_did,
    } = configure_alice_atm().await?;

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let recipient_did = bob_configuration().did;

    let msg = Message::build(
        Uuid::new_v4().into(),
        "https://didcomm.org/routing/2.0/forward".to_owned(),
        json!({ "next": recipient_did }),
    )
    .to(atm_did.clone())
    .from(actor_did.clone())
    .attachment(
        Attachment::json(json!({ "message": "plaintext attachment, mediator can read this" }))
            .finalize(),
    )
    .attachment(
        Attachment::base64(String::from(
            "ciphertext and iv which is encrypted by the recipient public key",
        ))
        .finalize(),
    );

    let msg = msg.created_time(now).expires_time(now + 300).finalize();

    // Pack the message
    let (msg, _) = atm
        .pack_encrypted(
            &msg,
            &atm_did.to_owned(),
            Some(&actor_did.clone()),
            Some(&actor_did.clone()),
        )
        .await
        .map_err(|e| ATMError::MsgSendError(format!("Error packing message: {}", e)))?;

    let response = atm
        .send_didcomm_message::<InboundMessageResponse>(&msg, true)
        .await?;

    info!("Response: {:?}", response);
    info!("Ok");

    Ok(())
}
