use std::time::Duration;

use affinidi_messaging_sdk::{
    config::Config, conversions::secret_from_str, errors::ATMError, protocols::Protocols, ATM,
};
use clap::Parser;
use serde_json::json;
use tracing::{error, info};
use tracing_subscriber::filter;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// network address if running in network mode (ws://127.0.0.1:8080/did/v1/ws)
    #[arg(short, long)]
    network_address: Option<String>,
    #[arg(short, long)]
    mediator_did: String,
}

#[tokio::main]
async fn main() -> Result<(), ATMError> {
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

    let mut config = Config::builder().with_my_did(my_did).with_atm_did(atm_did);

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

    let protocols = Protocols::new();

    /*let message = r#"
    {"protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIiwiYWxnIjoiRUNESC0xUFUrQTI1NktXIiwiZW5jIjoiQTI1NkNCQy1IUzUxMiIsInNraWQiOiJkaWQ6cGVlcjoyLlZ6Nk1rZ1dKZlZtUEVMb3pxNmFDeWNLM0NweEhOOFVwcGhuM1dTdVFrV1k2aXFzakYuRXpRM3NoZmI3dndRYVRKcUZrdDhuUmZvN051OTh0bWVZcGREZldncnFRaXREYXFYUnoja2V5LTIiLCJhcHUiOiJaR2xrT25CbFpYSTZNaTVXZWpaTmEyZFhTbVpXYlZCRlRHOTZjVFpoUTNsalN6TkRjSGhJVGpoVmNIQm9iak5YVTNWUmExZFpObWx4YzJwR0xrVjZVVE56YUdaaU4zWjNVV0ZVU25GR2EzUTRibEptYnpkT2RUazRkRzFsV1hCa1JHWlhaM0p4VVdsMFJHRnhXRko2STJ0bGVTMHkiLCJhcHYiOiI1a05fc2kyd2toMFVQX0ZlNVNLejVLQkJPNkYzMVRneXJBNEZ5Z1hTeExZIiwiZXBrIjp7ImNydiI6InNlY3AyNTZrMSIsImt0eSI6IkVDIiwieCI6IlluMllkX1BVUUZTSVQtaWt1WlFSZ0kyVmgzdFFOVXVLdWtEdWZ1clpHMzQiLCJ5IjoidkpRV1Y3U09jUWNtMkNwUkI1S3ZDMU5YeUxrS1hmdndwdVdlQlZ2RkY0RSJ9fQ","recipients":[{"header":{"kid":"did:peer:2.Vz6MkiToqovww7vYtxm1xNM15u9JzqzUFZ1k7s7MazYJUyAxv.EzQ3shQLqRUza6AMJFbPuMdvFRFWm1wKviQRnQSC1fScovJN4s.SeyJ0IjoiRElEQ29tbU1lc3NhZ2luZyIsInMiOnsidXJpIjoiaHR0cHM6Ly8xMjcuMC4wLjE6NzAzNyIsImEiOlsiZGlkY29tbS92MiJdLCJyIjpbXX19#key-2"},"encrypted_key":"_tK6Tu4uzgmKqJATtvQetmPSYC1dGKnLfDUOc6XLr4LDJHT1ujrAPtm-p2pIUd1Pewrt35CR0hK3-rdK0ffGSLJrP1ntrJ1K"}],"iv":"HP4BfkLKN5X0WTbu-PMV5g","ciphertext":"hQ4TLBC-yjGFx6GZonfzSM5DB8W9rNYeIW0eAPf1vxAkj0zuXkwsLx9tEyTbS1Oc46DDaIuMzFYcbfAyrioUNOUp-43OHGxtVKXues4wTNvMFVbWEkOq27bm18APj59JohT5QAd8Dn-iZ1vPl82MZbwxpymPWS0MQqdGB_OoY1Clm6nE7lDM3plgxbvH0VnUWopCrHHHhKE00esX7Ax5fO8RJLmdSt8DMPrVII3qOASDJIBHc2f5af06o7PytErkoN_d8oOyl2QhoQm7HWe1gWFXZcxxeZaFRqdJDcVrUJ_h3X7S21qxn38TdZ7r5fgGu9as0GvzkHCZbn9OBCjpQ6cUQNdB6NRuUXhjgWFH1vXALAiRn3OLsgiUVJM__Nr3EWLOgOeBLDz76K6LuXfFZApYjErf6doLbjMQ_vlb93r9-HNKy5xNHKZJF0i7qPCkZJUOPxm7DUsYt_zmq3gNs9C6DAug8Dp5ayBPriNUxgWBXpwaJyFB4idyMDs3rNyvsswm_Fz1ImiHT4w0DvCDPvgBbGgEot0wqzKdT-cjNAHaXIF_O-t1pzanrjUFU16VVeuyZ0m0WWB0qRnZWpADpWy_9Vdpjvvh3kw8BO05QwvTzdR82ed1R4JX2HHTZR3GNjvHy-y_b4sXK0yKAFrrSULcwLfJY-8tTLrfIlSssT9LMmBLJKBlhdIiG0gGyw0_Zf_3PocQ8a-MRcqdMFguKPAX49PcMnaSRkQkAPPYTPWp0zv8p_HREY3h8WIYWYhrfD_wAeJSAlaISxH-7RJkdnweauKyZ5sIQ4HZ7oqfw3ARR5IaJxI9N1H7gKuphLe27oYhHqbPb5OJmqlCOFi2MwmFruW9hZMitG9nYkr1GNF4rxfoT7kOfsLoEAkxmNHrBWqSoGdsCOtYCAbjeWNf6mtPoCaTfELf0hgzkOD5UXfgNO6oKoB76Y6YsuUNPbULPkEu20TDz9b2MFGkfyXONHNgA46MErNaWFM24J4-yK2hJ7YaiQ7i4x1ZvUTayoF4Co-1a4IS3Tc4kx1HF11vPzWRLQGgXtAh0LQKaoRhspMPUA2MSwWBu9Pf8cKBrY99NuQ1qVZaz8JmzikIDXEuLh6wPmny1OlvyWC4BvqPVX4-IwQV5c7Y_UiXs4p9_OU0Ioq-eA2SaZQRt1IXAodIZJ0mOf3L5om_ngoazEU9cc3N2BdwlrQ9i0fGtRmxC6nk03HqeFV182ZM8x8NFOIzRx_5lYBuTZVgjzV6vVVYK2LI_1hmGFkm5pr77vLidbSxH_oi7INANDcV9PzLKY5NB-1rdXvSUSkw5kQ2W_50HTTzLtluDD91q4DtJZg9rPI_7YFJUxWhJHOX5-iuitZNu788Cng1iHvKV2ylqIJ8GHp3f_FrIgfe8KFeULiuqQWbDgjp71NWPnk_GyNKWcGrcGx03sRV2U1l3kptkZ_Nv8yjsZygfW2iYM9vm_X-9f2rufPlpL2BmnzrmXpOBGIkk2TSXCYY5TzO65igG3yAE7-hrg02vIwbi7msUCMtiHcY","tag":"Tr-FOMqIRytEJvm1KSLFhalhErUUKZbIOWvJgyAaV2M"}
    "#;
    let response = atm.unpack(message).await?;
    info!("Unpacked: {:?}", response);
    */
    // For this example, we are forcing REST API only by closing the websocket
    // NOTE: We could have done this when we configured the ATM, but we are doing it here for demonstration purposes
    //atm.close_websocket().await?;

    // Enable live streaming
    protocols
        .message_pickup
        .toggle_live_delivery(&mut atm, true)
        .await?;

    // Send a Message Pickup 3.0 Status Request
    error!("Testing live_stream_next()!");
    let status = protocols
        .message_pickup
        .send_status_request(&mut atm, None, None, None)
        .await?;

    info!("Status: {:?}", status);

    if let Some((message, _)) = protocols
        .message_pickup
        .live_stream_next(&mut atm, Duration::from_secs(2))
        .await?
    {
        info!("Message: {:?}", message);
    }

    error!("Testing delivery-request()!");
    let response = protocols
        .message_pickup
        .send_delivery_request(&mut atm, None, None, None, None)
        .await?;

    let mut delete_ids: Vec<String> = Vec::new();

    for (message, _) in response {
        info!("Message: {}", message.id);
        delete_ids.push(message.id.clone());
    }

    let response = protocols
        .message_pickup
        .send_messages_received(&mut atm, None, None, &delete_ids, None)
        .await?;

    info!("Status: after send_messages_received() : {:?}", response);

    /* TODO: Need to complete this part of the protocol...

    tokio::time::sleep(Duration::from_secs(1)).await;
    error!("Testing live_stream_get()!");

    let response = protocols
        .message_pickup
        .send_status_request(&mut atm, None, None, None)
        .await?;

    info!("Status: {:?}", response);
    */

    // Disable live streaming
    protocols
        .message_pickup
        .toggle_live_delivery(&mut atm, false)
        .await?;

    tokio::time::sleep(Duration::from_secs(1)).await;

    atm.abort_websocket_task().await?;

    Ok(())
}
