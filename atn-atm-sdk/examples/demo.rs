use std::{fs, io::BufReader, sync::Arc};

use atn_atm_sdk::{
    config::Config,
    conversions::secret_from_str,
    errors::ATMError,
    messages::{fetch::FetchOptions, FetchDeletePolicy, Folder},
    ATM,
};
use did_peer::DIDPeer;
use rustls::{pki_types::CertificateDer, ClientConfig, RootCertStore};
use serde_json::json;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{connect_async, connect_async_tls_with_config, Connector};
use tracing::{debug, info, warn};
use tracing_subscriber::filter;
use url::Url;

#[tokio::main]
async fn main() -> Result<(), ATMError> {
    // construct a subscriber that prints formatted traces to stdout
    let subscriber = tracing_subscriber::fmt()
        // Use a more compact, abbreviated log format
        .pretty()
        .with_env_filter(filter::EnvFilter::from_default_env())
        .finish();
    // use that subscriber to process traces emitted after this point
    tracing::subscriber::set_global_default(subscriber).expect("Logging failed, exiting...");

    let my_did = "did:peer:2.Vz6MkgWJfVmPELozq6aCycK3CpxHN8Upphn3WSuQkWY6iqsjF.EzQ3shfb7vwQaTJqFkt8nRfo7Nu98tmeYpdDfWgrqQitDaqXRz";
    // Signing and verification key
    let v1 = json!({
        "crv": "Ed25519",
        "d": "LLWCf83n8VsUYq31zlZRe0NNMCcn1N4Dh85dGpIqSFw",
        "kty": "OKP",
        "x": "Hn8T4ZjjT0oJ6rjhqox8AykwC3GDFsJF6KkaYZExwQo"
    });

    // Encryption key
    let e1 = json!({
      "crv": "secp256k1",
      "d": "oi-dXG4EqfNODFPjv2vkieoLdbQZH9k6dwPDV8HDoms",
      "kty": "EC",
      "x": "DhfaXbhwo0KkOiyA5V1K1RZx6Ikr86h_lX5GOwxjmjE",
      "y": "PpYqybOwMsm64vftt-7gBCQPIUbglMmyy_6rloSSAPk"
    });

    let atm_did = "did:peer:2.Vz6MkiToqovww7vYtxm1xNM15u9JzqzUFZ1k7s7MazYJUyAxv.EzQ3shQLqRUza6AMJFbPuMdvFRFWm1wKviQRnQSC1fScovJN4s.SeyJ0IjoiRElEQ29tbU1lc3NhZ2luZyIsInMiOnsidXJpIjoiaHR0cHM6Ly8xMjcuMC4wLjE6NzAzNyIsImEiOlsiZGlkY29tbS92MiJdLCJyIjpbXX19";

    let config = Config::builder()
        .with_ssl_certificates(&mut vec![
            "../atn-atm-mediator/conf/keys/client.chain".into()
        ])
        .with_my_did(my_did)
        .with_atm_did(atm_did)
        .build()?;

    let mut atm = ATM::new(config, vec![Box::new(DIDPeer)]).await?;

    // Add our secrets to ATM Client - stays local.
    atm.add_secret(secret_from_str(&format!("{}#key-1", my_did), &v1));
    atm.add_secret(secret_from_str(&format!("{}#key-2", my_did), &e1));

    // Websocket testing
    atm.connect_websocket().await?;

    /*
    // Send a trust-ping message to ATM, will generate a PONG response
    let response = atm.send_ping(atm_did, true, true).await?;
    info!(
        "Successfully sent ping message responses({})",
        response.messages.len()
    );
    for (recipient, msg_id) in response.messages {
        debug!("recipient({}) message_id({})", recipient, msg_id);
    }
    for (recipient, err) in response.errors {
        warn!("recipient({}) error({})", recipient, err);
    }

    // Do we have messages in our inbox? Or how about queued still for delivery to others?
    let inbox_list = atm.list_messages(my_did, Folder::Inbox).await?;
    let outbox_list = atm.list_messages(my_did, Folder::Outbox).await?;
    info!(
        "Inbox contains {} messages. Outbox contains {} messages",
        inbox_list.len(),
        outbox_list.len()
    );

    // Fetch all messages from the inbox
    let messages = atm
        .fetch_messages(&FetchOptions {
            delete_policy: FetchDeletePolicy::OnReceive,
            ..Default::default()
        })
        .await?;
    info!("fetched {} messages", messages.success.len());
    let mut i = 1;
    for msg in &messages.success {
        let (_, _) = atm.unpack(&msg.msg.clone().unwrap()).await?;
        info!(
            "({}/{}): Message_id({}) fetched",
            i,
            messages.success.len(),
            msg.msg_id
        );
        i += 1;
    }*/

    // Retrieve the first message in the inbox
    /*if let Some(msg) = inbox_list.first() {
        let msgs = atm
            .get_messages(&GetMessagesRequest {
                delete: true,
                message_ids: vec![msg.msg_id.clone()],
            })
            .await?;

        for msg in msgs.success {
            let (message, _) = atm.unpack(&msg.msg.unwrap()).await?;
            info!(
                "Message received: {}, body = {:?}",
                msg.msg_id, message.body
            );
        }
    }*/
    // delete messages
    /*
        // Create list of messages to delete (who reads their inbox??)
    let delete_msgs: DeleteMessageRequest = DeleteMessageRequest {
        message_ids: inbox_list.iter().map(|m| m.msg_id.clone()).collect(),
    };

    let r = atm.delete_messages(&delete_msgs).await?;
    info!("Successfully deleted {} messages.", r.success.len());
    for (msg, err) in r.errors {
        warn!("failed to delete msg({}). Reason: {}", msg, err);
    }*/

    /*
        // Send a message to another DID via ATM
        atm.create_message(
            "Hello, World!",
            "did:example:to_address",
            MessageCreateOptions::default(),
        )
        .send()
        .await?;

        // I already have a DIDComm message, let's send it as well
        atm.send_didcomm(&didcomm_msg, &to_did, MessageSendOptions::default())
            .await?;
    */
    Ok(())
}
