use crate::{errors::ATMError, transports::websockets::ws_handler::WsHandlerMode};
use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_secrets_resolver::secrets::Secret;
use rustls::pki_types::CertificateDer;
use std::{fs::File, io::BufReader};
use tracing::error;

/// Configuration for the Affinidi Trusted Messaging (ATM) Service
/// You need to use the `builder()` method to create a new instance of `Config`
/// Example:
/// ```
/// use affinidi_messaging_sdk::config::Config;
///
/// let config = Config::builder().build();
/// ```
#[derive(Clone)]
pub struct ATMConfig {
    pub(crate) ssl_certificates: Vec<CertificateDer<'static>>,
    pub(crate) fetch_cache_limit_count: u32,
    pub(crate) fetch_cache_limit_bytes: u64,
    pub(crate) secrets: Vec<Secret>,
    pub(crate) did_resolver: Option<DIDCacheClient>,
    pub(crate) ws_handler_mode: WsHandlerMode,
}

impl ATMConfig {
    /// Returns a builder for `Config`
    /// Example:
    /// ```
    /// use affinidi_messaging_sdk::config::ATMConfig;
    ///
    /// let config = Config::builder().build();
    /// ```
    pub fn builder() -> ATMConfigBuilder {
        ATMConfigBuilder::default()
    }

    pub fn get_ssl_certificates(&self) -> &Vec<CertificateDer> {
        &self.ssl_certificates
    }
}

/// Builder for `ATMConfig`.
/// Example:
/// ```
/// use affinidi_messaging_sdk::config::ATMConfig;
///
/// // Create a new `ATMConfig` with defaults
/// let config = ATMConfig::builder().build();
/// ```
pub struct ATMConfigBuilder {
    ssl_certificates: Vec<String>,
    fetch_cache_limit_count: u32,
    fetch_cache_limit_bytes: u64,
    secrets: Vec<Secret>,
    did_resolver: Option<DIDCacheClient>,
    ws_handler_mode: WsHandlerMode,
}

impl Default for ATMConfigBuilder {
    fn default() -> Self {
        ATMConfigBuilder {
            ssl_certificates: vec![],
            fetch_cache_limit_count: 100,
            fetch_cache_limit_bytes: 1024 * 1024 * 10, // Defaults to 10MB Cache
            secrets: Vec::new(),
            did_resolver: None,
            ws_handler_mode: WsHandlerMode::Cached,
        }
    }
}

impl ATMConfigBuilder {
    /// Default starting constructor for `ATMConfigBuilder`
    pub fn new() -> ATMConfigBuilder {
        ATMConfigBuilder::default()
    }

    /// Add a list of SSL certificates to the configuration
    /// Each certificate should be a file path to a PEM encoded certificate
    pub fn with_ssl_certificates(mut self, ssl_certificates: &mut Vec<String>) -> Self {
        self.ssl_certificates.append(ssl_certificates);
        self
    }

    /// Add a secret to the SDK
    /// This is required to auto-start the websocket connection
    pub fn with_secret(mut self, secret: Secret) -> Self {
        self.secrets.push(secret);
        self
    }

    /// Add secrets to the SDK
    /// This is required to auto-start the websocket connection
    pub fn with_secrets(mut self, secrets: Vec<Secret>) -> Self {
        for secret in secrets {
            self.secrets.push(secret);
        }
        self
    }

    /// Set the maximum number of messages to cache in the fetch task
    /// Default: 100
    pub fn with_fetch_cache_limit_count(mut self, count: u32) -> Self {
        self.fetch_cache_limit_count = count;
        self
    }

    /// Set the maximum total size of messages to cache in the fetch task in bytes
    /// Default: 10MB (1024*1024*10)
    pub fn with_fetch_cache_limit_bytes(mut self, count: u64) -> Self {
        self.fetch_cache_limit_bytes = count;
        self
    }

    /// Use an external DID resolver for the SDK
    /// Useful if you want to configure the DID resolver externally.
    /// Default: ATM SDK will instantiate a local DID resolver
    pub fn with_external_did_resolver(mut self, did_resolver: &DIDCacheClient) -> Self {
        self.did_resolver = Some(did_resolver.clone());
        self
    }

    /// Set the mode for the websocket handler
    /// Default: Cached
    /// Cached: Messages are cached and sent to the SDK when requested (using the message_pickup protocol)
    /// DirectChannel: Messages are sent directly to the SDK via a channel
    pub fn with_ws_handler_mode(mut self, mode: WsHandlerMode) -> Self {
        self.ws_handler_mode = mode;
        self
    }

    pub fn build(self) -> Result<ATMConfig, ATMError> {
        // Process any custom SSL certificates
        let mut certs = vec![];
        let mut failed_certs = false;
        for cert in &self.ssl_certificates {
            let file = File::open(cert).map_err(|e| {
                ATMError::SSLError(format!(
                    "Couldn't open SSL certificate file ({})! Reason: {}",
                    cert, e
                ))
            })?;
            let mut reader = BufReader::new(file);

            for cert in rustls_pemfile::certs(&mut reader) {
                match cert {
                    Ok(cert) => certs.push(cert.into_owned()),
                    Err(e) => {
                        failed_certs = true;
                        error!("Couldn't parse SSL certificate! Reason: {}", e)
                    }
                }
            }
        }
        if failed_certs {
            return Err(ATMError::SSLError(
                "Couldn't parse all SSL certificates!".to_owned(),
            ));
        }

        Ok(ATMConfig {
            ssl_certificates: certs,
            fetch_cache_limit_count: self.fetch_cache_limit_count,
            fetch_cache_limit_bytes: self.fetch_cache_limit_bytes,
            secrets: self.secrets,
            did_resolver: self.did_resolver,
            ws_handler_mode: self.ws_handler_mode,
        })
    }
}
