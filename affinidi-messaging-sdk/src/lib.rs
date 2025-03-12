use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_messaging_didcomm::Message;
use affinidi_messaging_didcomm::UnpackMetadata;
use config::Config;
use delete_handler::DeletionHandlerCommands;
use errors::ATMError;
use profiles::Profiles;
use reqwest::{Certificate, Client};
use resolvers::secrets_resolver::AffinidiSecrets;
use rustls::ClientConfig as TlsClientConfig;
use rustls_platform_verifier::ConfigVerifierExt;
use secrets::Secret;
use ssi::dids::Document;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Receiver;
use tokio::sync::mpsc::Sender;
use tokio::sync::Mutex;
use tokio::sync::RwLock;
use tokio_tungstenite::Connector;
use tracing::Instrument;
use tracing::{debug, span};
use transports::websockets::ws_handler::WsHandlerCommands;
use transports::websockets::ws_handler::WsHandlerMode;

pub mod authentication;
pub mod config;
pub mod conversions;
pub mod delete_handler;
pub mod errors;
pub mod messages;
pub mod profiles;
pub mod protocols;
pub mod public;
mod resolvers;
pub mod secrets;
pub mod transports;

#[derive(Clone)]
pub struct ATM {
    pub(crate) inner: Arc<SharedState>,
}

/// Private SharedState struct for the ATM to be used across tasks
pub(crate) struct SharedState {
    pub(crate) config: Config,
    pub(crate) did_resolver: DIDCacheClient,
    pub(crate) secrets_resolver: AffinidiSecrets,
    pub(crate) client: Client,
    pub(crate) ws_connector: Connector,
    pub(crate) ws_handler_send_stream: Sender<WsHandlerCommands>, // Sends MPSC messages to the WebSocket handler
    pub(crate) ws_handler_recv_stream: Mutex<Receiver<WsHandlerCommands>>, // Receives MPSC messages from the WebSocket handler
    pub(crate) sdk_send_stream: Sender<WsHandlerCommands>, // Sends messages to the SDK
    pub(crate) profiles: Arc<RwLock<Profiles>>,
    pub(crate) direct_stream_sender: Option<broadcast::Sender<(Message, UnpackMetadata)>>, // Used if a client outside of ATM wants to direct stream from websocket
    pub(crate) deletion_handler_send_stream: Sender<delete_handler::DeletionHandlerCommands>, // Sends MPSC messages to the Deletion Handler
    pub(crate) deletion_handler_recv_stream:
        Mutex<Receiver<delete_handler::DeletionHandlerCommands>>, // Receives MPSC messages from the Deletion Handler
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
        let tls_config = TlsClientConfig::with_platform_verifier();

        // Set up the HTTP/HTTPS client
        let mut client = reqwest::ClientBuilder::new()
            .use_rustls_tls()
            .use_preconfigured_tls(tls_config.clone())
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

        let ws_connector = Connector::Rustls(Arc::new(tls_config));

        // Set up the DID Resolver
        let did_resolver = match &config.did_resolver {
            Some(did_resolver) => did_resolver.clone(),
            _ => {
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
            }
        };

        // Set up the channels for the WebSocket handler
        // Create a new channel with a capacity of at most 32. This communicates from SDK to the websocket handler
        let (sdk_tx, ws_handler_rx) = mpsc::channel::<WsHandlerCommands>(32);

        // Create a new channel with a capacity of at most 32. This communicates from websocket handler to SDK
        let (ws_handler_tx, sdk_rx) = mpsc::channel::<WsHandlerCommands>(32);

        // Create a new channel with a capacity of at most 32. This communicates from SDK to the deletion handler
        let (sdk_deletion_tx, deletion_sdk_rx) = mpsc::channel::<DeletionHandlerCommands>(32);

        // Create a new channel with a capacity of at most 32. This communicates from deletion handler to the SDK
        let (deletion_sdk_tx, sdk_deletion_rx) = mpsc::channel::<DeletionHandlerCommands>(32);

        let direct_stream_sender = match config.ws_handler_mode {
            WsHandlerMode::DirectChannel => {
                let (direct_stream_sender, _) = broadcast::channel(32);
                Some(direct_stream_sender)
            }
            _ => None,
        };

        let shared_state = SharedState {
            config: config.clone(),
            did_resolver,
            secrets_resolver: AffinidiSecrets::new(vec![]),
            client,
            ws_connector,
            ws_handler_send_stream: sdk_tx,
            ws_handler_recv_stream: Mutex::new(sdk_rx),
            sdk_send_stream: ws_handler_tx.clone(),
            profiles: Arc::new(RwLock::new(Profiles::default())),
            direct_stream_sender,
            deletion_handler_send_stream: sdk_deletion_tx,
            deletion_handler_recv_stream: Mutex::new(sdk_deletion_rx),
        };

        let atm = ATM {
            inner: Arc::new(shared_state),
        };

        // Add any pre-loaded secrets
        for secret in &config.secrets {
            atm.add_secret(secret);
        }

        // Start the websocket handler
        atm.start_websocket_handler(ws_handler_rx, ws_handler_tx)
            .await?;

        // Start the deletion handler
        atm.start_deletion_handler(deletion_sdk_rx, deletion_sdk_tx)
            .await?;

        debug!("ATM SDK initialized");

        Ok(atm)
    }

    pub async fn graceful_shutdown(&self) {
        debug!("Shutting down ATM SDK");

        // turn off incoming messages on websockets

        // Send a shutdown message to the Deletion Handler
        let _ = self.abort_deletion_handler().await;
        {
            let mut guard = self.inner.deletion_handler_recv_stream.lock().await;
            let _ = guard.recv().await;
            // Only ever send back a closing command
            // safe to exit now
            debug!("Deletion Handler stopped");
        }

        // Send a shutdown message to the WebSocket handler
        let _ = self.abort_websocket_task().await;
    }

    /// Adds a DID to the resolver
    /// This resolves the DID to the DID Document, and adds it to the list of known DIDs
    /// Returns the DIDDoc itself if successful, or an SDK Error
    pub async fn add_did(&self, did: &str) -> Result<Document, ATMError> {
        let _span = span!(tracing::Level::DEBUG, "add_did", did = did);

        async move {
            debug!("Adding DID to resolver");

            match self.inner.did_resolver.resolve(did).await {
                Ok(results) => Ok(results.doc),
                Err(err) => Err(ATMError::DIDError(format!(
                    "Couldn't resolve did ({}). Reason: {}",
                    did, err
                ))),
            }
        }
        .instrument(_span)
        .await
    }

    /// Adds secret to the secrets resolver
    /// You need to add the private keys of the DIDs you want to sign and encrypt messages with
    pub fn add_secret(&self, secret: &Secret) {
        self.inner.secrets_resolver.insert(secret.to_owned());
    }

    /// Adds a Vec of secrets to the secrets resolver
    pub async fn add_secrets(&self, secrets: &Vec<Secret>) {
        for secret in secrets {
            self.inner.secrets_resolver.insert(secret.clone());
        }
    }

    /// If you have set the ATM SDK to be in DirectChannel mode, you can get the inbound channel here
    /// This allows you to directly stream messages from the WebSocket Handler to your own client code
    pub fn get_inbound_channel(&self) -> Option<broadcast::Receiver<(Message, UnpackMetadata)>> {
        self.inner
            .direct_stream_sender
            .as_ref()
            .map(|sender| sender.subscribe())
    }
}
