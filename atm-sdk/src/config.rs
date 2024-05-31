use std::{fs::File, io::Read};

use reqwest::Certificate;

use crate::errors::ATMError;

/// Configuration for the Affinidi Trusted Messaging (ATM) Service
/// You need to use the `builder()` method to create a new instance of `Config`
/// Example:
/// ```
/// use atm_sdk::config::Config;
///
/// let config = Config::builder().build();
/// ```
#[derive(Clone)]
pub struct Config {
    pub(crate) my_did: String,
    ssl_certificates: Vec<Certificate>,
}

impl Config {
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

    pub(crate) fn get_ssl_certificates(&self) -> &Vec<Certificate> {
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
#[derive(Default)]
pub struct ConfigBuilder {
    ssl_certificates: Vec<String>,
    my_did: Option<String>,
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

    pub fn build(self) -> Result<Config, ATMError> {
        // Process any custom SSL certificates
        let mut certs = vec![];
        for cert in &self.ssl_certificates {
            let mut buf = vec![];
            File::open(cert)
                .map_err(|e| {
                    ATMError::SSLError(format!(
                        "Couldn't open SSL certificate file ({})! Reason: {}",
                        cert, e
                    ))
                })?
                .read_to_end(&mut buf)
                .map_err(|e| {
                    ATMError::SSLError(format!(
                        "Couldn't read SSL certificate file ({})! Reason: {}",
                        cert, e
                    ))
                })?;
            let cert = Certificate::from_pem_bundle(&buf).map_err(|e| {
                ATMError::SSLError(format!(
                    "Couldn't parse SSL certificate file ({})! Reason: {}",
                    cert, e
                ))
            })?;
            for cert in cert {
                certs.push(cert);
            }
        }

        let my_did = if let Some(my_did) = self.my_did {
            my_did
        } else {
            return Err(ATMError::ConfigError(
                "You must provide a DID for the SDK, used for authentication!".to_owned(),
            ));
        };

        Ok(Config {
            ssl_certificates: certs,
            my_did,
        })
    }
}
