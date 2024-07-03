use atn_atm_sdk::{
    config::Config, conversions::secret_from_str, errors::ATMError, protocols::Protocols,
    transports::SendMessageResponse, ATM,
};
use did_peer::DIDPeer;
use serde_json::json;
use tracing::{debug, error, info, warn};
use tracing_subscriber::filter;

#[tokio::main]
async fn main() -> Result<(), ATMError> {
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

    let atm_did = "did:peer:2.Vz6MkiToqovww7vYtxm1xNM15u9JzqzUFZ1k7s7MazYJUyAxv.EzQ3shQLqRUza6AMJFbPuMdvFRFWm1wKviQRnQSC1fScovJN4s.SeyJ0IjoiRElEQ29tbU1lc3NhZ2luZyIsInMiOnsidXJpIjoiaHR0cHM6Ly8xMjcuMC4wLjE6NzAzNyIsImEiOlsiZGlkY29tbS92MiJdLCJyIjpbXX19";

    let config = Config::builder()
        .with_ssl_certificates(&mut vec![
            "../atn-atm-mediator/conf/keys/client.chain".into()
        ])
        .with_my_did(my_did)
        .with_atm_did(atm_did)
        .with_secret(secret_from_str(&format!("{}#key-1", my_did), &v1))
        .with_secret(secret_from_str(&format!("{}#key-2", my_did), &e1))
        .build()?;

    // Create a new ATM Client
    let mut atm = ATM::new(config, vec![Box::new(DIDPeer)]).await?;

    // Going to work with higher level DIDComm protocols
    let protocols = Protocols::default();

    // For this example, we are forcing REST API only by closing the websocket
    // NOTE: We could have done this when we configured the ATM, but we are doing it here for demonstration purposes
    atm.close_websocket().await?;

    // Send a Message Pickup 3.0 Status Request
    let response = protocols
        .message_pickup
        .send_status_request(&mut atm, None, None)
        .await?;

    // Check if we received a status
    if let SendMessageResponse::RestAPI(Some(status)) = response {
        info!("Status: {:?}", status);
    } else {
        warn!("No status received");
    }

    Ok(())
}
