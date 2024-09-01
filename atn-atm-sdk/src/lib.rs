use atn_atm_didcomm::secrets::Secret;
use atn_did_cache_sdk::DIDCacheClient;
use config::Config;
use errors::ATMError;
use messages::AuthorizationResponse;
use reqwest::{Certificate, Client};
use resolvers::secrets_resolver::AffinidiSecrets;
use rustls::{ClientConfig, RootCertStore};
use ssi::dids::Document;
use std::sync::Arc;
use tokio::sync::mpsc::Receiver;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinHandle;
use tokio_tungstenite::Connector;
use tracing::{debug, span, warn};
use websockets::ws_handler::WSCommand;

mod authentication;
pub mod config;
pub mod conversions;
pub mod errors;
pub mod messages;
pub mod protocols;
mod resolvers;
pub mod transports;

pub mod websockets {
    #[doc(inline)]
    pub use crate::transports::websockets::*;
}

pub struct ATM<'c> {
    pub(crate) config: Config<'c>,
    did_resolver: DIDCacheClient,
    secrets_resolver: AffinidiSecrets,
    pub(crate) client: Client,
    authenticated: bool,
    jwt_tokens: Option<AuthorizationResponse>,
    ws_connector: Connector,
    pub(crate) ws_enabled: bool,
    ws_handler: Option<JoinHandle<()>>,
    ws_send_stream: Option<Sender<WSCommand>>,
    ws_recv_stream: Option<Receiver<WSCommand>>,
}

/// Affinidi Trusted Messaging SDK
/// This is the top level struct for the SSK
///
/// Example:
/// ```
/// use atm_sdk::ATM;
///
/// let config = Config::builder().build();
/// let mut atm = ATM::new(config);
///
/// // Add the DID:Peer method
/// atm.add_did_method(Box::new(DIDPeer));
///
/// let response = atm.ping("did:example:123", true);
/// ```
impl<'c> ATM<'c> {
    /// Creates a new instance of the SDK with a given configuration
    /// You need to add at least the DID Method for the SDK DID to work
    pub async fn new(config: Config<'c>) -> Result<ATM<'c>, ATMError> {
        // Set a process wide default crypto provider.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        // Set up the HTTP/HTTPS client
        let mut client = reqwest::ClientBuilder::new()
            .use_rustls_tls()
            .https_only(config.ssl_only)
            .user_agent("Affinidi Trusted Messaging");

        for cert in config.get_ssl_certificates() {
            client = client.add_root_certificate(
                Certificate::from_der(cert.to_vec().as_slice()).map_err(|e| {
                    ATMError::SSLError(format!("Couldn't add certificate. Reason: {}", e))
                })?,
            );
        }

        let client = match client.build() {
            Ok(client) => client,
            Err(e) => {
                return Err(ATMError::TransportError(format!(
                    "Couldn't create HTTPS Client. Reason: {}",
                    e
                )))
            }
        };

        // Set up the WebSocket Client
        let mut root_store = RootCertStore::empty();
        if config.get_ssl_certificates().is_empty() {
            debug!("Use native SSL Certs");

            for cert in
                rustls_native_certs::load_native_certs().expect("Could not load platform certs")
            {
                root_store.add(cert).map_err(|e| {
                    warn!("Couldn't add cert: {:?}", e);
                    ATMError::SSLError(format!("Couldn't add cert. Reason: {}", e))
                })?;
            }
        } else {
            debug!("Use custom SSL Certs");
            for cert in config.get_ssl_certificates() {
                root_store.add(cert.to_owned()).map_err(|e| {
                    warn!("Couldn't add cert: {:?}", e);
                    ATMError::SSLError(format!("Couldn't add cert. Reason: {}", e))
                })?;
            }
        }

        let ws_config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let ws_connector = Connector::Rustls(Arc::new(ws_config));

        let did_resolver = match DIDCacheClient::new(
            atn_did_cache_sdk::config::ClientConfigBuilder::default().build(),
        )
        .await
        {
            Ok(config) => config,
            Err(err) => {
                return Err(ATMError::DIDError(format!(
                    "Couldn't create DID resolver! Reason: {}",
                    err
                )))
            }
        };

        let mut atm = ATM {
            config: config.clone(),
            did_resolver,
            secrets_resolver: AffinidiSecrets::new(vec![]),
            client,
            authenticated: false,
            jwt_tokens: None,
            ws_connector,
            ws_enabled: config.ws_enabled,
            ws_handler: None,
            ws_send_stream: None,
            ws_recv_stream: None,
        };

        // Add our own DID to the DID_RESOLVER
        atm.add_did(&config.my_did).await?;
        // Add our ATM DID to the DID_RESOLVER
        atm.add_did(&config.atm_did).await?;

        // Add any pre-loaded secrets
        for secret in config.secrets {
            atm.add_secret(secret);
        }

        // Start the websocket connection if enabled
        if atm.ws_enabled {
            atm.start_websocket_task().await?;
        }
        debug!("ATM SDK initialized");

        Ok(atm)
    }

    /// Adds a DID to the resolver
    /// This resolves the DID to the DID Document, and adds it to the list of known DIDs
    /// Returns the DIDDoc itself if successful, or an SDK Error
    pub async fn add_did(&mut self, did: &str) -> Result<Document, ATMError> {
        let _span = span!(tracing::Level::DEBUG, "add_did", did = did).entered();
        debug!("Adding DID to resolver");

        match self.did_resolver.resolve(did).await {
            Ok(results) => Ok(results.doc),
            Err(err) => Err(ATMError::DIDError(format!(
                "Couldn't resolve did ({}). Reason: {}",
                did, err
            ))),
        }
    }

    /// Adds required secrets to the secrets resolver
    /// You need to add the private keys of the DIDs you want to sign and encrypt messages with
    pub fn add_secret(&mut self, secret: Secret) {
        self.secrets_resolver.insert(secret);
    }
}
