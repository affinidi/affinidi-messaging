use crate::errors::ATMError;
use rustls::pki_types::CertificateDer;
use std::{fs::File, io::BufReader};
use tracing::error;

/// Configuration for the Affinidi Trusted Messaging (ATM) Service
/// You need to use the `builder()` method to create a new instance of `Config`
/// Example:
/// ```
/// use atm_sdk::config::Config;
///
/// let config = Config::builder().build();
/// ```
#[derive(Clone)]
pub struct Config<'a> {
    pub(crate) my_did: String,
    ssl_certificates: Vec<CertificateDer<'a>>,
    pub(crate) atm_api: String,
    pub(crate) atm_api_ws: String,
    pub(crate) atm_did: String,
    pub(crate) ssl_only: bool,
}

impl<'a> Config<'a> {
    /// Returns a builder for `Config`
    /// Example:
    /// ```
    /// use atm_sdk::config::Config;
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
/// use atm_sdk::config::Config;
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
                    Ok(cert) => certs.push(cert),
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

        let my_did = if let Some(my_did) = self.my_did {
            my_did
        } else {
            return Err(ATMError::ConfigError(
                "You must provide a DID for the SDK, used for authentication!".to_owned(),
            ));
        };

        let atm_api = if let Some(atm_url) = self.atm_api {
            atm_url
        } else {
            // TODO: Change this to the production URL
            "https://localhost:7037/atm/v1".to_string()
        };

        // convert the ATM API URL to a WebSocket URL
        let atm_api_ws = if atm_api.starts_with("http://") {
            format!("ws://{}/ws", atm_api.split_at(7).1)
        } else if atm_api.starts_with("https://") {
            format!("wss://{}/ws", atm_api.split_at(8).1)
        } else {
            return Err(ATMError::ConfigError(
                "ATM API URL must start with http:// or https://".to_string(),
            ));
        };

        let atm_did = if let Some(atm_did) = self.atm_did {
            atm_did
        } else {
            return Err(ATMError::ConfigError(
                "You must provide the DID for the ATM service!".to_owned(),
            ));
        };

        Ok(Config {
            ssl_certificates: certs,
            my_did,
            atm_api,
            atm_api_ws,
            atm_did,
            ssl_only: self.ssl_only,
        })
    }
}