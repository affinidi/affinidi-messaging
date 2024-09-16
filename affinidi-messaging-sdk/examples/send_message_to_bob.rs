use affinidi_messaging_sdk::{
  config::Config, 
  conversions::secret_from_str, 
  errors::ATMError,
  messages::sending::InboundMessageResponse,
  ATM,
};
use affinidi_messaging_didcomm::{Attachment, Message};
use clap::Parser;
use serde_json::json;
use tracing::info;
use std::time::SystemTime;
use tracing_subscriber::filter;
use uuid::Uuid;
use std::error::Error;

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
async fn main()-> Result<(), Box<dyn Error>> {
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

  info!("Running with address: {}", &args.network_address);
  info!("Running with mediator_did: {}", &args.mediator_did);
  info!("Running with ssl_certificates: {}", &args.ssl_certificates);

  // DIDs of sender(your DID) and recipient
  let recipient_did = "did:peer:2.Vz6Mkihn2R3M8nY62EFJ7MAVXu7YxsTnuS5iAhmn3qKJbkdFf.EzQ3shpZRBUtewwzYiueXgDqs1bvGNkSyGoRgsbZJXt3TTb9jD.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHBzOi8vbG9jYWxob3N0OjcwMzcvIiwiYWNjZXB0IjpbImRpZGNvbW0vdjIiXSwicm91dGluZ19rZXlzIjpbXX0sImlkIjpudWxsfQ";

  // DID of the Mediator
  let mediator_did = &args.mediator_did;
  let sender_did = "did:peer:2.Vz6MkgWJfVmPELozq6aCycK3CpxHN8Upphn3WSuQkWY6iqsjF.EzQ3shfb7vwQaTJqFkt8nRfo7Nu98tmeYpdDfWgrqQitDaqXRz";
  
  // Signing and verification key
  let verification_key1 = json!({
      "crv": "Ed25519",
      "d": "LLWCf83n8VsUYq31zlZRe0NNMCcn1N4Dh85dGpIqSFw",
      "kty": "OKP",
      "x": "Hn8T4ZjjT0oJ6rjhqox8AykwC3GDFsJF6KkaYZExwQo"
  });

  // Encryption key
  let encryption_key1 = json!({
    "crv": "secp256k1",
    "d": "oi-dXG4EqfNODFPjv2vkieoLdbQZH9k6dwPDV8HDoms",
    "kty": "EC",
    "x": "DhfaXbhwo0KkOiyA5V1K1RZx6Ikr86h_lX5GOwxjmjE",
    "y": "PpYqybOwMsm64vftt-7gBCQPIUbglMmyy_6rloSSAPk"
  });

  let mut config = Config::builder()
      .with_my_did(sender_did)
      .with_atm_did(mediator_did)
      .with_websocket_disabled();

  config = config
      .with_atm_api(&args.network_address)
      .with_ssl_certificates(&mut vec![args.ssl_certificates.into()]);

  // Create a new ATM Client
  let mut atm = ATM::new(config.build()?).await?;
  // Add sender's secrets to ATM Client - these keys stays local.
  atm.add_secret(secret_from_str(&format!("{}#key-1", sender_did), &verification_key1));
  atm.add_secret(secret_from_str(&format!("{}#key-2", sender_did), &encryption_key1));

  let now = SystemTime::now()
      .duration_since(SystemTime::UNIX_EPOCH)
      .unwrap()
      .as_secs();

  let msg = Message::build(
      Uuid::new_v4().into(),
      "https://didcomm.org/routing/2.0/forward".to_owned(),
      json!({ "next": recipient_did }),
  )
      .to(mediator_did.to_owned())
      .from(sender_did.to_string())
      .attachment(Attachment::json(json!({ "message": "plaintext attachment, mediator can read this" })).finalize())
      .attachment(Attachment::base64(String::from("ciphertext and iv which is encrypted by the recipient public key")).finalize());

  let msg = msg.created_time(now).expires_time(now + 300).finalize();

  // Pack the message
  let (msg, _) = atm
      .pack_encrypted(
        &msg,
        mediator_did,
        Some(sender_did),
        Some(sender_did)
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