use affinidi_messaging_didcomm::{Attachment, Message};
use affinidi_messaging_sdk::{
    errors::ATMError,
    messages::{fetch::FetchOptions, sending::InboundMessageResponse, FetchDeletePolicy},
};
use clap::Parser;
use serde_json::json;
use std::error::Error;
use std::time::SystemTime;
use tracing::{debug, info};
use uuid::Uuid;

mod common;

use common::{configure_alice_atm, ConfigureAtmResult};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    network_address: String,
    #[arg(short, long)]
    ssl_certificates: String,
    #[arg(short, long)]
    mediator_did: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let ConfigureAtmResult {
        mut atm,
        atm_did,
        actor_did,
    } = configure_alice_atm().await?;

    // You normally don't need to call authenticate() as it is called automatically
    atm.authenticate().await?;

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let msg_to_me = Message::build(
        Uuid::new_v4().into(),
        "https://didcomm.org/routing/2.0/forward".to_owned(),
        json!({ "next": actor_did.clone() }), // "next" is an addressee of attachments. Mediator will repack them to "next"
    )
    .to(atm_did.clone()) // mediator should forward a message, so mediator is receiver
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

    let msg_to_me = msg_to_me
        .created_time(now)
        .expires_time(now + 300)
        .finalize();

    // Pack the message
    let (msg, _) = atm
        .pack_encrypted(
            &msg_to_me,
            &atm_did,
            Some(&actor_did.clone()),
            Some(&actor_did.clone()),
        )
        .await
        .map_err(|e| ATMError::MsgSendError(format!("Error packing message: {}", e)))?;

    let response = atm
        .send_didcomm_message::<InboundMessageResponse>(&msg, true)
        .await?;

    debug!("msg: {:?}", response);

    // Get the messages from ATM
    let msgs = atm
        .fetch_messages(&FetchOptions {
            limit: 10,
            start_id: None,
            delete_policy: FetchDeletePolicy::OnReceive,
        })
        .await?;

    for msg in msgs.success {
        let (received_msg_unpacked, _) = atm.unpack(&msg.msg.unwrap()).await?;
        debug!("msg: {:?}", received_msg_unpacked);
    }

    info!("OK");

    Ok(())
}
