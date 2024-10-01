use affinidi_did_resolver_cache_sdk::{config::ClientConfigBuilder, DIDCacheClient};
use affinidi_messaging_didcomm::{secrets::SecretsResolver, Message, PackEncryptedOptions};
use affinidi_messaging_mediator::{resolvers::affinidi_secrets::AffinidiSecrets, server::start};
use affinidi_messaging_sdk::{
    config::Config,
    conversions::secret_from_str,
    errors::ATMError,
    messages::{AuthenticationChallenge, AuthorizationResponse, SuccessResponse},
};
use core::panic;
use reqwest::{Certificate, Client, ClientBuilder};
use serde_json::json;
use std::time::SystemTime;
use uuid::Uuid;

const MY_DID: &str = "did:peer:2.Vz6MkjS2RdXzLJqkRQYTUNi7G5vY7YqL1cXqoemERGADuz3dr.Ez6MknGys6JPaaCmwqwrakMfo1ehrsw8DN2vnFH3LvgUSje3T.EzQ3shu53gkVSo1PzDFyXDdm9LzzK7JnkTf5zM5oq37EatqBJY.SeyJ0IjoiZG0iLCJzIjp7InVyaSI6Imh0dHBzOi8vbG9jYWxob3N0OjcwMzciLCJhY2NlcHQiOlsiZGlkY29tbS92MiJdLCJyb3V0aW5nX2tleXMiOltdfSwiaWQiOm51bGx9";
const MEDIATOR_API: &str = "https://localhost:7037/mediator/v1";

#[tokio::test]
async fn test_mediator_server() {
    _start_mediator_server().await;

    let config = Config::builder()
        .with_ssl_certificates(&mut vec![
            "../affinidi-messaging-mediator/conf/keys/client.chain".into(),
        ])
        .build()
        .unwrap();

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
    let did_resolver = DIDCacheClient::new(ClientConfigBuilder::default().build())
        .await
        .unwrap();
    let secrets_resolver = AffinidiSecrets::new(vec![
        secret_from_str(&format!("{}#key-2", MY_DID), &e1),
        secret_from_str(&format!("{}#key-1", MY_DID), &v1),
    ]);
    // Set up the HTTP/HTTPS client
    let mut client = ClientBuilder::new()
        .use_rustls_tls()
        .https_only(true)
        .user_agent("Affinidi Trusted Messaging");

    for cert in config.get_ssl_certificates() {
        client =
            client.add_root_certificate(Certificate::from_der(cert.to_vec().as_slice()).unwrap());
    }

    let client = match client.build() {
        Ok(client) => client,
        Err(e) => return assert!(false, "{:?}", e),
    };

    let mediator_did = _well_known(client.clone()).await;

    let authentication_challenge = _authenticate_challenge(client.clone()).await;

    let auth_response_msg = _create_auth_challenge_response(
        &authentication_challenge,
        MY_DID,
        &mediator_did,
        "authenticate",
    );
    let authentication_response = _authenticate(
        client.clone(),
        auth_response_msg,
        MY_DID,
        &mediator_did,
        &did_resolver,
        &secrets_resolver,
    )
    .await;

    assert!(!authentication_response.access_token.is_empty());
    assert!(!authentication_response.refresh_token.is_empty());
}

async fn _start_mediator_server() {
    tokio::spawn(async move { start().await });
    println!("Server running");
}

async fn _well_known(client: Client) -> String {
    let well_known_did_atm_api = format!("{}/.well-known/did", MEDIATOR_API);

    let res = client
        .get(well_known_did_atm_api)
        .header("Content-Type", "application/json")
        .send()
        .await
        .unwrap();

    let status = res.status();
    assert_eq!(status, 200);
    println!("API response: status({})", status);
    let body = res.text().await.unwrap();

    let body = serde_json::from_str::<SuccessResponse<String>>(&body)
        .ok()
        .unwrap();
    let did = if let Some(did) = body.data {
        did
    } else {
        panic!("Not able to fetch mediator did");
    };
    assert!(!did.is_empty());

    did
}

async fn _authenticate_challenge(client: Client) -> AuthenticationChallenge {
    let res = client
        .post(format!("{}/authenticate/challenge", MEDIATOR_API))
        .header("Content-Type", "application/json")
        .body(format!("{{\"did\": \"{}\"}}", MY_DID).to_string())
        .send()
        .await
        .unwrap();

    let status = res.status();
    assert_eq!(status, 200);

    let body = res.text().await.unwrap();

    if !status.is_success() {
        println!("Failed to get authentication challenge. Body: {:?}", body);
        assert!(
            false,
            "Failed to get authentication challenge. Body: {:?}",
            body
        );
    }
    let body = serde_json::from_str::<SuccessResponse<AuthenticationChallenge>>(&body)
        .ok()
        .unwrap();

    let challenge = if let Some(challenge) = body.data {
        challenge
    } else {
        panic!("No challenge received from ATM");
    };
    assert!(!challenge.challenge.is_empty());
    assert!(!challenge.session_id.is_empty());

    challenge
}

async fn _authenticate<'sr>(
    client: Client,
    auth_response: Message,
    my_did: &str,
    atm_did: &str,
    did_resolver: &DIDCacheClient,
    secrets_resolver: &'sr (dyn SecretsResolver + 'sr + Sync),
) -> AuthorizationResponse {
    let (auth_msg, _) = auth_response
        .pack_encrypted(
            atm_did,
            Some(my_did),
            Some(my_did),
            did_resolver,
            secrets_resolver,
            &PackEncryptedOptions::default(),
        )
        .await
        .map_err(|e| {
            ATMError::MsgSendError(format!(
                "Couldn't pack authentication response message: {:?}",
                e
            ))
        })
        .unwrap();

    let res = client
        .post(format!("{}/authenticate", MEDIATOR_API))
        .header("Content-Type", "application/json")
        .body(auth_msg)
        .send()
        .await
        .map_err(|e| {
            ATMError::TransportError(format!("Could not post authentication response: {:?}", e))
        })
        .unwrap();

    let status = res.status();
    println!("Authentication response: status({})", status);

    let body = res.text().await.unwrap();

    if !status.is_success() {
        println!("Failed to get authentication response. Body: {:?}", body);
        panic!("Failed to get authentication response");
    }
    let body = serde_json::from_str::<SuccessResponse<AuthorizationResponse>>(&body).unwrap();

    if let Some(tokens) = body.data {
        return tokens.clone();
    } else {
        panic!("No tokens received from ATM");
    }
}

fn _create_auth_challenge_response(
    body: &AuthenticationChallenge,
    my_did: &str,
    atm_did: &str,
    protocol_message: &str,
) -> Message {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    Message::build(
        Uuid::new_v4().into(),
        format!("https://affinidi.com/atm/1.0/{}", protocol_message),
        json!(body),
    )
    .to(atm_did.to_owned())
    .from(my_did.to_owned())
    .created_time(now)
    .expires_time(now + 60)
    .finalize()
}
