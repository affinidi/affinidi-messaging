use atn_atm_didcomm::did::DIDDoc;
use atn_atm_didcomm::did::DIDResolver as DidcommDIDResolver;
use atn_atm_didcomm::secrets::Secret;
use config::Config;
use errors::ATMError;
use messages::AuthorizationResponse;
use reqwest::Certificate;
use reqwest::Client;
use resolvers::did_resolver::AffinidiDIDResolver;
use resolvers::secrets_resolver::AffinidiSecrets;
use rustls::ClientConfig;
use rustls::RootCertStore;
use ssi::did::{DIDMethod, DIDMethods};
use ssi::did_resolve::DIDResolver as SSIDIDResolver;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_tungstenite::Connector;
use tokio_tungstenite::MaybeTlsStream;
use tokio_tungstenite::WebSocketStream;
use tracing::debug;
use tracing::span;
use tracing::warn;

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
    did_methods_resolver: DIDMethods<'c>,
    did_resolver: AffinidiDIDResolver,
    secrets_resolver: AffinidiSecrets,
    pub(crate) client: Client,
    authenticated: bool,
    jwt_tokens: Option<AuthorizationResponse>,
    ws_connector: Connector,
    pub(crate) ws_enabled: bool,
    pub(crate) ws_stream: Option<WebSocketStream<MaybeTlsStream<TcpStream>>>,
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
    pub async fn new(
        config: Config<'c>,
        did_methods: Vec<Box<dyn DIDMethod>>,
    ) -> Result<ATM<'c>, ATMError> {
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
            for cert in rustls_native_certs::load_native_certs()
                .map_err(|e| ATMError::SSLError(e.to_string()))?
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

        let mut atm = ATM {
            config: config.clone(),
            did_methods_resolver: DIDMethods::default(),
            did_resolver: AffinidiDIDResolver::new(vec![]),
            secrets_resolver: AffinidiSecrets::new(vec![]),
            client,
            authenticated: false,
            jwt_tokens: None,
            ws_connector,
            ws_enabled: config.ws_enabled,
            ws_stream: None,
        };

        for method in did_methods {
            atm.add_did_method(method);
        }
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
            atm.start_websocket().await?;
        }

        Ok(atm)
    }

    /// Adds a DID Method that the resolvers can work with
    /// NOTE: DIDMethod is a trait from the `ssi` crate
    /// NOTE: As a result we add them after the initial creation of the ATM
    ///       So that we get around silly Rust borrowing rules on dyn traits
    ///
    /// Example:
    /// ```
    /// atm.add_did_method(Box::new(DIDPeer));
    /// ```
    pub fn add_did_method(&mut self, did_method: Box<dyn DIDMethod>) -> &Self {
        self.did_methods_resolver.insert(did_method);
        self
    }

    /// Adds a DID to the resolver
    /// This resolves the DID to the DID Document, and adds it to the list of known DIDs
    /// Returns the DIDDoc itself if successful, or an SDK Error
    pub async fn add_did(&mut self, did: &str) -> Result<DIDDoc, ATMError> {
        let _span = span!(tracing::Level::DEBUG, "add_did", did = did).entered();
        debug!("Adding DID to resolver");
        let (res_meta, doc_opt, _) = self
            .did_methods_resolver
            .resolve(did, &Default::default())
            .await;

        let doc = if let Some(doc) = doc_opt {
            doc
        } else {
            debug!("Couldn't resolve DID, returning error");
            return Err(ATMError::DIDError(format!(
                "Could not resolve DID ({}). Reason: {}",
                did,
                res_meta.error.unwrap_or("Unknown".to_string())
            )));
        };

        let doc = conversions::convert_did_format(&doc).await?;
        self.did_resolver.insert(&doc);
        debug!("Successfully added DID to resolver");

        Ok(doc)
    }

    /// Adds required secrets to the secrets resolver
    /// You need to add the private keys of the DIDs you want to sign and encrypt messages with
    pub fn add_secret(&mut self, secret: Secret) {
        self.secrets_resolver.insert(secret);
    }
}
