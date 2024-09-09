use affinidi_messaging_didcomm::Message;
use affinidi_messaging_sdk::{
    config::Config,
    conversions::secret_from_str,
    errors::ATMError,
    // messages::{fetch::FetchOptions, sending::InboundMessageResponse, FetchDeletePolicy},
    messages::sending::InboundMessageResponse,
    ATM,
};
use clap::Parser;
use serde_json::json;
use std::error::Error;
use std::time::SystemTime;
use tracing_subscriber::filter;
use uuid::Uuid;

// use tracing::info;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// network address if running in network mode (https://localhost:7037/atm/v1)
    #[arg(short, long)]
    network_address: Option<String>,
    #[arg(short, long)]
    mediator_did: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // **************************************************************
    // *** Initial setup
    // **************************************************************
    let args = Args::parse();

    // construct a subscriber that prints formatted traces to stdout
    let subscriber = tracing_subscriber::fmt()
        // Use a more compact, abbreviated log format
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

    let atm_did = &args.mediator_did;
    let to_did = atm_did;

    // TODO: in the future we likely want to pull this from the DID itself
    let mut config = Config::builder()
        .with_my_did(my_did)
        .with_atm_did(atm_did)
        .with_websocket_disabled();

    if let Some(address) = &args.network_address {
        println!("Running in network mode with address: {}", address);
        config = config
            .with_ssl_certificates(&mut vec!["./certs/mediator-key.pem".into()])
            .with_atm_api(address);
    } else {
        println!("Running in local mode.");
        config = config.with_ssl_certificates(&mut vec![
            "../affinidi-messaging-mediator/conf/keys/client.chain".into(),
        ]);
    }

    // Create a new ATM Client
    let mut atm = ATM::new(config.build()?).await?;

    // Add our secrets to ATM Client - stays local.
    atm.add_secret(secret_from_str(&format!("{}#key-1", my_did), &v1));
    atm.add_secret(secret_from_str(&format!("{}#key-2", my_did), &e1));

    // You normally don't need to call authenticate() as it is called automatically

    atm.authenticate().await?;

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let msg = Message::build(
        Uuid::new_v4().into(),
        "https://didcomm.org/trust-ping/2.0/ping".to_owned(),
        json!("Hello World! Message sent via DIDComm"),
    )
    .to(to_did.to_owned())
    .from(my_did.to_string());

    let msg = msg.created_time(now).expires_time(now + 300).finalize();

    println!("Message Build");

    println!("Send message: {:?}", msg);

    // Pack the message
    let (msg, _) = atm
        .pack_encrypted(&msg, to_did, Some(my_did), Some(my_did))
        .await
        .map_err(|e| ATMError::MsgSendError(format!("Error packing message: {}", e)))?;

    let response = atm
        .send_didcomm_message::<InboundMessageResponse>(&msg, true)
        .await?;

    println!("Response message: {:?}", response);

    // // Get the PONG message from ATM
    // let msgs = atm
    //     .fetch_messages(&FetchOptions {
    //         limit: 10,
    //         start_id: None,
    //         delete_policy: FetchDeletePolicy::DoNotDelete
    //     })
    //     .await?;

    // for msg in msgs.success {
    //     atm.unpack(&msg.msg.unwrap()).await?;
    //     info!("Messages sent: {}", msg.msg_id);
    // }

    Ok(())
}
