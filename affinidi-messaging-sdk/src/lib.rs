use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_messaging_didcomm::secrets::Secret;
use config::Config;
use errors::ATMError;
use profiles::Profiles;
use reqwest::{Certificate, Client};
use resolvers::secrets_resolver::AffinidiSecrets;
use rustls::{ClientConfig, RootCertStore};
use ssi::dids::Document;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Receiver;
use tokio::sync::mpsc::Sender;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio_tungstenite::Connector;
use tracing::{debug, span, warn};
use transports::websockets::ws_handler::WsHandlerCommands;

pub mod authentication;
pub mod config;
pub mod conversions;
pub mod errors;
pub mod messages;
pub mod profiles;
pub mod protocols;
pub mod public;
mod resolvers;
pub mod secrets;
pub mod transports;

pub struct ATM {
    pub(crate) inner: Arc<RwLock<SharedState>>,
}

/// Private SharedState struct for the ATM to be used across tasks
pub(crate) struct SharedState {
    pub(crate) config: Config,
    pub(crate) did_resolver: DIDCacheClient,
    pub(crate) secrets_resolver: AffinidiSecrets,
    pub(crate) client: Client,
    pub(crate) ws_connector: Connector,
    pub(crate) ws_handler: Option<JoinHandle<()>>,
    pub(crate) ws_handler_send_stream: Sender<WsHandlerCommands>,
    pub(crate) ws_handler_recv_stream: Receiver<WsHandlerCommands>,
    pub(crate) profiles: Profiles,
}

/// Affinidi Trusted Messaging SDK
/// This is the top level struct for the SSK
///
/// Example:
/// ```ignore
/// use affinidi_messaging_sdk::ATM;
/// use affinidi_messaging_sdk::config::Config;
///
/// let config = Config::builder().build();
/// let mut atm = ATM::new(config);
///
/// // Add the DID:Peer method
/// atm.add_did_method(Box::new(DIDPeer));
///
/// let response = atm.ping("did:example:123", true);
/// ```
impl ATM {
    /// Creates a new instance of the SDK with a given configuration
    /// You need to add at least the DID Method for the SDK DID to work
    pub async fn new(config: Config) -> Result<ATM, ATMError> {
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

        // Set up the DID Resolver
        let did_resolver = if let Some(did_resolver) = &config.did_resolver {
            did_resolver.clone()
        } else {
            match DIDCacheClient::new(
                affinidi_did_resolver_cache_sdk::config::ClientConfigBuilder::default().build(),
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
            }
        };

        // Set up the channels for the WebSocket handler
        // Create a new channel with a capacity of at most 32. This communicates from SDK to the websocket handler
        let (sdk_tx, sdk_rx) = mpsc::channel::<WsHandlerCommands>(32);

        // Create a new channel with a capacity of at most 32. This communicates from websocket handler to SDK
        let (ws_handler_tx, ws_handler_rx) = mpsc::channel::<WsHandlerCommands>(32);

        let shared_state = SharedState {
            config: config.clone(),
            did_resolver,
            secrets_resolver: AffinidiSecrets::new(vec![]),
            client,
            ws_connector,
            ws_handler: None,
            ws_handler_send_stream: sdk_tx,
            ws_handler_recv_stream: ws_handler_rx,
            profiles: Profiles::default(),
        };

        let atm = ATM {
            inner: Arc::new(RwLock::new(shared_state)),
        };

        // Add any pre-loaded secrets
        for secret in &config.secrets {
            atm.add_secret(secret).await;
        }

        // Start the websocket handler
        atm.start_websocket_handler(sdk_rx, ws_handler_tx).await?;
        debug!("ATM SDK initialized");

        Ok(atm)
    }

    /// Adds a DID to the resolver
    /// This resolves the DID to the DID Document, and adds it to the list of known DIDs
    /// Returns the DIDDoc itself if successful, or an SDK Error
    pub async fn add_did(&self, did: &str) -> Result<Document, ATMError> {
        let _span = span!(tracing::Level::DEBUG, "add_did", did = did).entered();
        debug!("Adding DID to resolver");

        match self.inner.write().await.did_resolver.resolve(did).await {
            Ok(results) => Ok(results.doc),
            Err(err) => Err(ATMError::DIDError(format!(
                "Couldn't resolve did ({}). Reason: {}",
                did, err
            ))),
        }
    }

    /// Adds secret to the secrets resolver
    /// You need to add the private keys of the DIDs you want to sign and encrypt messages with
    pub async fn add_secret(&self, secret: &Secret) {
        self.inner
            .write()
            .await
            .secrets_resolver
            .insert(secret.to_owned());
    }

    /// Adds a Vec of secrets to the secrets resolver
    pub async fn add_secrets(&mut self, secrets: Vec<Secret>) {
        let mut lock = self.inner.write().await;
        for secret in secrets {
            lock.secrets_resolver.insert(secret);
        }
    }
}
