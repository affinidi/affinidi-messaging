use super::{did_conversion::convert_did, errors::MediatorError};
use crate::resolvers::affinidi_secrets::AffinidiSecrets;
use async_convert::{async_trait, TryFrom};
use base64::prelude::*;
use did_peer::DIDPeer;
use didcomm::{did::DIDDoc, secrets::Secret};
use jsonwebtoken::{DecodingKey, EncodingKey};
use regex::{Captures, Regex};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use ssi::{
    did::DIDMethods,
    did_resolve::{DIDResolver, ResolutionInputMetadata},
};
use std::{
    collections::HashSet,
    env, fmt,
    fs::File,
    io::{self, BufRead},
    path::Path,
};
use tracing::{event, Level};
use tracing_subscriber::filter::LevelFilter;

/// Database Struct contains database and storage of messages related configuration details
#[derive(Debug, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub database_url: String,
    pub database_pool_size: String,
    pub database_timeout: String,
    pub max_message_size: String,
    pub max_queued_messages: String,
    pub message_expiry_minutes: String,
}

/// SecurityConfig Struct contains security related configuration details
#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub use_ssl: String,
    pub ssl_certificate_file: String,
    pub ssl_key_file: String,
    pub jwt_authorization_secret: String,
}

/// ConfigRaw Struct is used to deserialize the configuration file
/// We then convert this to the Config Struct
#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigRaw {
    pub log_level: String,
    pub listen_address: String,
    pub mediator_did: String,
    pub mediator_secrets: String,
    pub mediator_allowed_dids: String,
    pub mediator_denied_dids: String,
    pub database: DatabaseConfig,
    pub security: SecurityConfig,
}

#[derive(Clone)]
pub struct Config {
    pub log_level: LevelFilter,
    pub listen_address: String,
    pub mediator_did: String,
    pub mediator_did_doc: DIDDoc,
    pub mediator_secrets: AffinidiSecrets,
    pub mediator_allowed_dids: HashSet<String>,
    pub mediator_denied_dids: HashSet<String>,
    pub database_url: String,
    pub database_pool_size: usize,
    pub database_timeout: u32,
    pub max_message_size: u32,
    pub max_queued_messages: u32,
    pub message_expiry_minutes: u32,
    pub use_ssl: bool,
    pub ssl_certificate_file: String,
    pub ssl_key_file: String,
    pub jwt_encoding_key: Option<EncodingKey>,
    pub jwt_decoding_key: Option<DecodingKey>,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("log_level", &self.log_level)
            .field("listen_address", &self.listen_address)
            .field("mediator_did", &self.mediator_did)
            .field("mediator_did_doc", &"Hidden")
            .field(
                "mediator_secrets",
                &format!("({}) secrets loaded", self.mediator_secrets.len()),
            )
            .field(
                "mediator_allowed_dids",
                &&format!("({}) allowed_dids loaded", self.mediator_allowed_dids.len()),
            )
            .field(
                "mediator_denied_dids",
                &&format!("({}) denied_dids loaded", self.mediator_denied_dids.len()),
            )
            .field("use_ssl", &self.use_ssl)
            .field("database_url", &self.database_url)
            .field("database_pool_size", &self.database_pool_size)
            .field("database_timeout", &self.database_timeout)
            .field("max_message_size", &self.max_message_size)
            .field("max_queued_messages", &self.max_queued_messages)
            .field("message_expiry_minutes", &self.message_expiry_minutes)
            .field("ssl_certificate_file", &self.ssl_certificate_file)
            .field("ssl_key_file", &self.ssl_key_file)
            .field("jwt_encoding_key?", &self.jwt_encoding_key.is_some())
            .field("jwt_decoding_key?", &self.jwt_decoding_key.is_some())
            .finish()
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            log_level: LevelFilter::INFO,
            listen_address: "".into(),
            mediator_did: "".into(),
            mediator_did_doc: DIDDoc {
                id: "".into(),
                key_agreement: Vec::new(),
                authentication: Vec::new(),
                verification_method: Vec::new(),
                service: Vec::new(),
            },
            mediator_secrets: AffinidiSecrets::new(vec![]),
            mediator_allowed_dids: HashSet::new(),
            mediator_denied_dids: HashSet::new(),
            database_url: "redis://127.0.0.1/".into(),
            database_pool_size: 10,
            database_timeout: 2,
            max_message_size: 1048576,
            max_queued_messages: 100,
            message_expiry_minutes: 10080,
            use_ssl: true,
            ssl_certificate_file: "".into(),
            ssl_key_file: "".into(),
            jwt_encoding_key: None,
            jwt_decoding_key: None,
        }
    }
}

#[async_trait]
impl TryFrom<ConfigRaw> for Config {
    type Error = MediatorError;

    async fn try_from(raw: ConfigRaw) -> Result<Self, Self::Error> {
        let mut config = Config {
            log_level: match raw.log_level.as_str() {
                "trace" => LevelFilter::TRACE,
                "debug" => LevelFilter::DEBUG,
                "info" => LevelFilter::INFO,
                "warn" => LevelFilter::WARN,
                "error" => LevelFilter::ERROR,
                _ => LevelFilter::INFO,
            },
            listen_address: raw.listen_address,
            mediator_did: raw.mediator_did.clone(),
            database_url: raw.database.database_url,
            database_pool_size: raw.database.database_pool_size.parse().unwrap_or(10),
            database_timeout: raw.database.database_timeout.parse().unwrap_or(2),
            max_message_size: raw.database.max_message_size.parse().unwrap_or(1048576),
            max_queued_messages: raw.database.max_queued_messages.parse().unwrap_or(100),
            message_expiry_minutes: raw.database.message_expiry_minutes.parse().unwrap_or(10080),
            use_ssl: raw.security.use_ssl.parse().unwrap(),
            ssl_certificate_file: raw.security.ssl_certificate_file,
            ssl_key_file: raw.security.ssl_key_file,
            ..Default::default()
        };

        // Resolve mediator DID Doc and expand keys
        let mut did_resolver = DIDMethods::default();
        did_resolver.insert(Box::new(DIDPeer));

        let (_, doc_opt, _) = did_resolver
            .resolve(&raw.mediator_did, &ResolutionInputMetadata::default())
            .await;

        let doc_opt = match doc_opt {
            Some(doc) => doc,
            None => {
                return Err(MediatorError::ConfigError(
                    "NA".into(),
                    format!("Could not resolve mediator DID ({})", raw.mediator_did),
                ));
            }
        };

        let doc_opt = match DIDPeer::expand_keys(&doc_opt).await {
            Ok(doc_opt) => doc_opt,
            Err(err) => {
                return Err(MediatorError::ConfigError(
                    "NA".into(),
                    format!("Could not expand mediator DID ({})", err),
                ));
            }
        };

        config.mediator_did_doc = convert_did(&doc_opt)?;

        // Load mediator secrets
        config.mediator_secrets = load_secrets(&raw.mediator_secrets)?;

        // Load mediator allowed DID's
        config.mediator_allowed_dids = load_did_list(&raw.mediator_allowed_dids)?;

        // Load mediator denied DID's
        config.mediator_denied_dids = load_did_list(&raw.mediator_denied_dids)?;

        // Create the JWT encoding and decoding keys
        let jwt_secret = BASE64_URL_SAFE_NO_PAD
            .decode(&raw.security.jwt_authorization_secret)
            .map_err(|err| {
                event!(Level::ERROR, "Could not create JWT key pair. {}", err);
                MediatorError::ConfigError(
                    "NA".into(),
                    format!("Could not create JWT key pair. {}", err),
                )
            })?;
        config.jwt_encoding_key = Some(EncodingKey::from_ed_der(&jwt_secret));

        let pair = Ed25519KeyPair::from_pkcs8(&jwt_secret).map_err(|err| {
            event!(Level::ERROR, "Could not create JWT key pair. {}", err);
            MediatorError::ConfigError(
                "NA".into(),
                format!("Could not create JWT key pair. {}", err),
            )
        })?;
        config.jwt_decoding_key = Some(DecodingKey::from_ed_der(pair.public_key().as_ref()));

        Ok(config)
    }
}

/// Loads the secret data into the Config file.
/// Only supports a file containing a JSON array of secrets
/// TODO: Add support for other methods of getting these secrets (AWS Secrets Manager, etc.)
fn load_secrets(secrets: &str) -> Result<AffinidiSecrets, MediatorError> {
    let (type_, file_name) = secrets.split_at(7);
    if type_ != "file://" {
        return Err(MediatorError::ConfigError(
            "NA".into(),
            "Only file:// is supported for mediator secrets".into(),
        ));
    }

    Ok(AffinidiSecrets::new(
        serde_json::from_str::<Vec<Secret>>(&read_file_lines(file_name)?.concat()).map_err(
            |err| {
                event!(Level::ERROR, "Could not open file({}). {}", file_name, err);
                MediatorError::ConfigError(
                    "NA".into(),
                    format!("Could not open file({}). {}", file_name, err),
                )
            },
        )?,
    ))
}

/// Loads from a file a list of DID's into a HashSet
/// Useful for the allow/deny lists for the mediator
fn load_did_list(file_name: &str) -> Result<HashSet<String>, MediatorError> {
    Ok(HashSet::from_iter(
        read_file_lines(file_name)?.iter().cloned(),
    ))
}

/// Read the primary configuration file for the mediator
/// Returns a ConfigRaw struct, that still needs to be processed for additional information
/// and conversion to Config struct
pub fn read_config_file(file_name: &str) -> Result<ConfigRaw, MediatorError> {
    // Read configuration file parameters
    event!(Level::INFO, "Config file({})", file_name);
    let raw_config = read_file_lines(file_name)?;

    event!(Level::DEBUG, "raw_config = {:?}", raw_config);
    let config_with_vars = expand_env_vars(&raw_config);
    match toml::from_str(&config_with_vars.join("\n")) {
        Ok(config) => Ok(config),
        Err(err) => {
            event!(
                Level::ERROR,
                "Could not parse configuration settings. {:?}",
                err
            );
            Err(MediatorError::ConfigError(
                "NA".into(),
                format!("Could not parse configuration settings. Reason: {:?}", err),
            ))
        }
    }
}

/// Reads a file and returns a vector of strings, one for each line in the file.
/// It also strips any lines starting with a # (comments)
/// You can join the Vec back into a single string with `.join("\n")`
/// ```
/// let lines = read_file_lines("file.txt")?;
/// let file_contents = lines.join("\n");
/// ```
fn read_file_lines<P>(file_name: P) -> Result<Vec<String>, MediatorError>
where
    P: AsRef<Path>,
{
    let file = File::open(file_name.as_ref()).map_err(|err| {
        event!(
            Level::ERROR,
            "Could not open file({}). {}",
            file_name.as_ref().display(),
            err
        );
        MediatorError::ConfigError(
            "NA".into(),
            format!(
                "Could not open file({}). {}",
                file_name.as_ref().display(),
                err
            ),
        )
    })?;

    let mut lines = Vec::new();
    for line in io::BufReader::new(file).lines().map_while(Result::ok) {
        // Strip comments out
        if !line.starts_with('#') {
            lines.push(line);
        }
    }

    Ok(lines)
}

/// Replaces all strings ${VAR_NAME:default_value}
/// with the corresponding environment variables (e.g. value of ${VAR_NAME})
/// or with `default_value` if the variable is not defined.
fn expand_env_vars(raw_config: &Vec<String>) -> Vec<String> {
    let re = Regex::new(r"\$\{(?P<env_var>[A-Z_]{1,}[0-9A-Z_]*):(?P<default_value>.*)\}").unwrap();
    let mut result: Vec<String> = Vec::new();
    for line in raw_config {
        result.push(
            re.replace_all(line, |caps: &Captures| match env::var(&caps["env_var"]) {
                Ok(val) => val,
                Err(_) => (caps["default_value"]).into(),
            })
            .into_owned(),
        );
    }
    result
}
