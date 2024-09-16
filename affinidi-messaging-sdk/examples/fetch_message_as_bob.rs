use affinidi_messaging_sdk::messages::{fetch::FetchOptions, FetchDeletePolicy};
use std::error::Error;
use tracing::info;

mod common;

use common::{configure_bob_atm, ConfigureAtmResult};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let ConfigureAtmResult {
        mut atm,
        atm_did: _,
        actor_did: _,
    } = configure_bob_atm().await?;
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
        info!("Message received: {:?}", received_msg_unpacked);
    }

    info!("Ok");

    Ok(())
}
