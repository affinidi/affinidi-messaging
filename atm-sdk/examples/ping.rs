use atm_sdk::{config::Config, conversions::secret_from_str, errors::ATMError, ATM};
use did_peer::DIDPeer;
use serde_json::json;
use tracing::{debug, Level};

#[tokio::main]
async fn main() -> Result<(), ATMError> {
    // construct a subscriber that prints formatted traces to stdout
    let subscriber = tracing_subscriber::fmt()
        // Use a more compact, abbreviated log format
        .compact()
        .with_max_level(Level::DEBUG)
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

    let mediator_did = "did:peer:2.Vz6MkiXGPX2fvUinqRETvsbS2PDjwSksnoU9X94eFwUjRbbZJ.EzQ3shXbp9EFX7JzH2rPVfEfAEAYA4ifv4qY5sLcRgZxLHY42W.SeyJ0IjoiRElEQ29tbU1lc3NhZ2luZyIsInMiOnsidXJpIjoiaHR0cHM6Ly8xMjcuMC4wLjE6NzAzNyIsImEiOlsiZGlkY29tbS92MiJdLCJyIjpbXX19";

    let config = Config::builder()
        .with_ssl_certificates(&mut vec!["../conf/keys/client.chain".into()])
        .with_my_did(my_did)
        .build()?;

    let mut atm = ATM::new(config, vec![Box::new(DIDPeer)]).await?;

    // Now to add our secrets to ATM
    atm.add_secret(secret_from_str(&format!("{}#key-1", my_did), &v1));
    atm.add_secret(secret_from_str(&format!("{}#key-2", my_did), &e1));

    // Send the ping message
    // Sending to the mediator, anonymous message, expecting a response (which will get dropped as we're anonymous)
    atm.send_ping(mediator_did, true, true).await?;

    println!("Good!");
    Ok(())
}
