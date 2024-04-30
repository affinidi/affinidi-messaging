use std::{
    collections::HashSet,
    env, fmt,
    fs::File,
    io::{self, BufRead},
    path::Path,
};

use super::{did_conversion::convert_did, errors::MediatorError};
use async_convert::{async_trait, TryFrom};
use did_peer::DIDPeer;
use didcomm::{did::DIDDoc, secrets::Secret};
use regex::{Captures, Regex};
use serde::{Deserialize, Serialize};
use ssi::{
    did::DIDMethods,
    did_resolve::{DIDResolver, ResolutionInputMetadata},
};
use tracing::{event, Level};
use tracing_subscriber::filter::LevelFilter;

/// ConfigRaw Struct is used to deserialize the configuration file
/// We then convert this to the Config Struct
#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigRaw {
    pub log_level: String,
    pub listen_address: String,
    pub database_file: String,
    pub database_max_size_mb: String,
    pub mediator_did: String,
    pub mediator_secrets: String,
    pub mediator_allowed_dids: String,
    pub mediator_denied_dids: String,
}

pub struct Config {
    pub log_level: LevelFilter,
    pub listen_address: String,
    pub database_file: String,
    pub database_max_size_mb: u64,
    pub mediator_did: String,
    pub mediator_did_doc: DIDDoc,
    pub mediator_secrets: Vec<Secret>,
    pub mediator_allowed_dids: HashSet<String>,
    pub mediator_denied_dids: HashSet<String>,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("log_level", &self.log_level)
            .field("listen_address", &self.listen_address)
            .field("database_file", &self.database_file)
            .field("database_max_size_mb", &self.database_max_size_mb)
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
            .finish()
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            log_level: LevelFilter::INFO,
            listen_address: "".into(),
            database_file: "".into(),
            database_max_size_mb: 100,
            mediator_did: "".into(),
            mediator_did_doc: DIDDoc {
                id: "".into(),
                key_agreement: Vec::new(),
                authentication: Vec::new(),
                verification_method: Vec::new(),
                service: Vec::new(),
            },
            mediator_secrets: Vec::new(),
            mediator_allowed_dids: HashSet::new(),
            mediator_denied_dids: HashSet::new(),
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
            database_file: raw.database_file,
            database_max_size_mb: raw.database_max_size_mb.parse::<u64>().unwrap_or(100),
            mediator_did: raw.mediator_did.clone(),
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

        Ok(config)
    }
}

/// Loads the secret data into the Config file.
/// Only supports a file containing a JSON array of secrets
/// TODO: Add support for other methods of getting these secrets (AWS Secrets Manager, etc.)
fn load_secrets(secrets: &str) -> Result<Vec<Secret>, MediatorError> {
    let (type_, file_name) = secrets.split_at(7);
    if type_ != "file://" {
        return Err(MediatorError::ConfigError(
            "NA".into(),
            "Only file:// is supported for mediator secrets".into(),
        ));
    }

    serde_json::from_str::<Vec<Secret>>(&read_file_lines(file_name)?.concat()).map_err(|err| {
        event!(Level::ERROR, "Could not open file({}). {}", file_name, err);
        MediatorError::ConfigError(
            "NA".into(),
            format!("Could not open file({}). {}", file_name, err),
        )
    })
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
