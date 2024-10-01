use crate::errors::ATMError;
use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_messaging_didcomm::secrets::Secret;
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
pub struct Config<'a> {
    pub(crate) my_did: Option<String>,
    pub(crate) ssl_certificates: Vec<CertificateDer<'a>>,
    pub(crate) atm_api: String,
    pub(crate) atm_api_ws: String,
    pub(crate) atm_did: Option<String>,
    pub(crate) ssl_only: bool,
    pub(crate) ws_enabled: bool,
    pub(crate) fetch_cache_limit_count: u32,
    pub(crate) fetch_cache_limit_bytes: u64,
    pub(crate) secrets: Vec<Secret>,
    pub(crate) did_resolver: Option<DIDCacheClient>,
}

impl<'a> Config<'a> {
    /// Returns a builder for `Config`
    /// Example:
    /// ```
    /// use affinidi_messaging_sdk::config::Config;
    ///
    /// let config = Config::builder().build();
    /// ```
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::default()
    }

    pub fn get_ssl_certificates(&self) -> &Vec<CertificateDer> {
        &self.ssl_certificates
    }
}

/// Builder for `Config`.
/// Example:
/// ```
/// use affinidi_messaging_sdk::config::Config;
///
/// // Create a new `Config` with defaults
/// let config = Config::builder().build();
/// ```
pub struct ConfigBuilder {
    ssl_certificates: Vec<String>,
    my_did: Option<String>,
    atm_api: Option<String>,
    atm_api_ws: Option<String>,
    atm_did: Option<String>,
    ssl_only: bool,
    ws_enabled: bool,
    fetch_cache_limit_count: u32,
    fetch_cache_limit_bytes: u64,
    secrets: Vec<Secret>,
    did_resolver: Option<DIDCacheClient>,
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        ConfigBuilder {
            ssl_certificates: vec![],
            my_did: None,
            atm_api: None,
            atm_api_ws: None,
            atm_did: None,
            ssl_only: true,
            ws_enabled: true,
            fetch_cache_limit_count: 100,
            fetch_cache_limit_bytes: 1024 * 1024 * 10, // Defaults to 10MB Cache
            secrets: Vec::new(),
            did_resolver: None,
        }
    }
}

impl ConfigBuilder {
    /// Basic starting constructor for `ConfigBuilder`
    pub fn new() -> ConfigBuilder {
        ConfigBuilder::default()
    }

    /// Add a list of SSL certificates to the configuration
    /// Each certificate should be a file path to a PEM encoded certificate
    pub fn with_ssl_certificates(mut self, ssl_certificates: &mut Vec<String>) -> Self {
        self.ssl_certificates.append(ssl_certificates);
        self
    }

    /// Add the DID for the client itself to ATM
    pub fn with_my_did(mut self, my_did: &str) -> Self {
        self.my_did = Some(my_did.to_owned());
        self
    }

    /// Add the URL for the ATM API
    pub fn with_atm_api(mut self, api_url: &str) -> Self {
        self.atm_api = Some(api_url.to_owned());
        self
    }

    /// Add the URL for the ATM API WebSocket
    /// Defaults: ATM API URL with `/ws` appended
    pub fn with_atm_websocket_api(mut self, ws_api_url: &str) -> Self {
        self.atm_api_ws = Some(ws_api_url.to_owned());
        self
    }

    /// Add the DID for the ATM service itself
    pub fn with_atm_did(mut self, atm_did: &str) -> Self {
        self.atm_did = Some(atm_did.to_owned());
        self
    }

    /// Allow non-SSL connections to the ATM service
    /// This is not recommended for production use
    /// Default: `true`
    pub fn with_non_ssl(mut self) -> Self {
        self.ssl_only = false;
        self
    }

    /// Disables WebSocket connections to the ATM service
    /// This is not recommended for production use
    /// Default: `true`
    pub fn with_websocket_disabled(mut self) -> Self {
        self.ws_enabled = false;
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

    pub fn build<'a>(self) -> Result<Config<'a>, ATMError> {
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

        let atm_api = if let Some(atm_url) = self.atm_api {
            atm_url
        } else {
            // TODO: Change this to the production URL
            "https://localhost:7037/mediator/v1".to_string()
        };

        // convert the ATM API URL to a WebSocket URL
        let atm_api_ws = if let Some(atm_api_ws) = self.atm_api_ws {
            atm_api_ws
        } else if atm_api.starts_with("http://") {
            format!("ws://{}/ws", atm_api.split_at(7).1)
        } else if atm_api.starts_with("https://") {
            format!("wss://{}/ws", atm_api.split_at(8).1)
        } else {
            return Err(ATMError::ConfigError(
                "ATM API URL must start with http:// or https://".to_string(),
            ));
        };

        Ok(Config {
            ssl_certificates: certs,
            my_did: self.my_did,
            atm_api,
            atm_api_ws,
            atm_did: self.atm_did,
            ssl_only: self.ssl_only,
            ws_enabled: self.ws_enabled,
            fetch_cache_limit_count: self.fetch_cache_limit_count,
            fetch_cache_limit_bytes: self.fetch_cache_limit_bytes,
            secrets: self.secrets,
            did_resolver: self.did_resolver,
        })
    }
}
