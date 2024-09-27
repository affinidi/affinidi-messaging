use super::errors::MediatorError;
use crate::resolvers::affinidi_secrets::AffinidiSecrets;
use affinidi_did_resolver_cache_sdk::config::{ClientConfig, ClientConfigBuilder};
use async_convert::{async_trait, TryFrom};
use aws_config::{self, BehaviorVersion, Region, SdkConfig};
use aws_sdk_secretsmanager;
use aws_sdk_ssm::types::ParameterType;
use base64::prelude::*;
use http::HeaderValue;
use jsonwebtoken::{DecodingKey, EncodingKey};
use regex::{Captures, Regex};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use tower_http::cors::{Any, CorsLayer};

use std::{
    env, fmt,
    fs::File,
    io::{self, BufRead},
    path::Path,
};
use tracing::{event, info, Level};
use tracing_subscriber::{filter::LevelFilter, reload::Handle, EnvFilter, Registry};

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    pub listen_address: String,
    pub api_prefix: String,
    pub admin_did: String,
}

/// Database Struct contains database and storage of messages related configuration details
#[derive(Debug, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub database_url: String,
    pub database_pool_size: String,
    pub database_timeout: String,
}

/// SecurityConfig Struct contains security related configuration details
#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub mediator_secrets: String,
    pub use_ssl: String,
    pub ssl_certificate_file: String,
    pub ssl_key_file: String,
    pub jwt_authorization_secret: String,
    pub cors_allow_origin: Option<String>,
}

/// StreamingConfig Struct contains live streaming related configuration details
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StreamingConfig {
    pub enabled: String,
    pub uuid: String,
}

/// DIDResolverConfig Struct contains live streaming related configuration details
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DIDResolverConfig {
    pub address: Option<String>,
    pub cache_capacity: String,
    pub cache_ttl: String,
    pub network_timeout: String,
    pub network_limit: String,
}

/// LimitsConfig Struct contains limits used by Affinidi Messenger
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LimitsConfig {
    pub attachments_max_count: usize,
    pub crypto_operations_per_message: usize,
    pub forward_task_queue: usize,
    pub http_size: usize,
    pub local_max_acl: usize,
    pub message_expiry_minutes: usize,
    pub message_size: usize,
    pub queued_messages: usize,
    pub to_keys_per_recipient: usize,
    pub to_recipients: usize,
    pub ws_size: usize,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        LimitsConfig {
            attachments_max_count: 20,
            crypto_operations_per_message: 1000,
            forward_task_queue: 50_000,
            http_size: 10_485_760,
            local_max_acl: 1_000,
            message_expiry_minutes: 10_080,
            message_size: 1_048_576,
            queued_messages: 100,
            to_keys_per_recipient: 100,
            to_recipients: 100,
            ws_size: 10_485_760,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LimitsConfigRaw {
    pub attachments_max_count: String,
    pub crypto_operations_per_message: String,
    pub forward_task_queue: String,
    pub http_size: String,
    pub local_max_acl: String,
    pub message_expiry_minutes: String,
    pub message_size: String,
    pub queued_messages: String,
    pub to_keys_per_recipient: String,
    pub to_recipients: String,
    pub ws_size: String,
}

impl std::convert::TryFrom<LimitsConfigRaw> for LimitsConfig {
    type Error = MediatorError;

    fn try_from(raw: LimitsConfigRaw) -> Result<Self, Self::Error> {
        Ok(LimitsConfig {
            attachments_max_count: raw.attachments_max_count.parse().unwrap_or(20),
            crypto_operations_per_message: raw
                .crypto_operations_per_message
                .parse()
                .unwrap_or(1000),
            forward_task_queue: raw.forward_task_queue.parse().unwrap_or(50_000),
            http_size: raw.http_size.parse().unwrap_or(10_485_760),
            local_max_acl: raw.local_max_acl.parse().unwrap_or(1_000),
            message_expiry_minutes: raw.message_expiry_minutes.parse().unwrap_or(10_080),
            message_size: raw.message_size.parse().unwrap_or(1_048_576),
            queued_messages: raw.queued_messages.parse().unwrap_or(100),
            to_keys_per_recipient: raw.to_keys_per_recipient.parse().unwrap_or(100),
            to_recipients: raw.to_recipients.parse().unwrap_or(100),
            ws_size: raw.ws_size.parse().unwrap_or(10_485_760),
        })
    }
}

/// ProcessorsConfig Struct contains configuration specific to different processors
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProcessorsConfig {
    pub forwarding: ForwardingConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ProcessorsConfigRaw {
    pub forwarding: ForwardingConfigRaw,
}

/// ForwardingConfig Struct contains configuration specific to DIDComm Routing/Forwarding
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ForwardingConfig {
    pub enabled: bool,
    pub future_time_limit: u64,
}

impl Default for ForwardingConfig {
    fn default() -> Self {
        ForwardingConfig {
            enabled: true,
            future_time_limit: 86400,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ForwardingConfigRaw {
    pub enabled: String,
    pub future_time_limit: String,
}

impl std::convert::TryFrom<ForwardingConfigRaw> for ForwardingConfig {
    type Error = MediatorError;

    fn try_from(raw: ForwardingConfigRaw) -> Result<Self, Self::Error> {
        Ok(ForwardingConfig {
            enabled: raw.enabled.parse().unwrap_or(true),
            future_time_limit: raw.future_time_limit.parse().unwrap_or(86400),
        })
    }
}

impl DIDResolverConfig {
    pub fn convert(&self) -> ClientConfig {
        let mut config = ClientConfigBuilder::default()
            .with_cache_capacity(self.cache_capacity.parse().unwrap_or(1000))
            .with_cache_ttl(self.cache_ttl.parse().unwrap_or(300))
            .with_network_timeout(self.network_timeout.parse().unwrap_or(5))
            .with_network_cache_limit_count(self.network_limit.parse().unwrap_or(100));

        if let Some(address) = &self.address {
            config = config.with_network_mode(address);
        }

        config.build()
    }
}

/// ConfigRaw Struct is used to deserialize the configuration file
/// We then convert this to the Config Struct
#[derive(Debug, Serialize, Deserialize)]
struct ConfigRaw {
    pub log_level: String,
    pub mediator_did: String,
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub security: SecurityConfig,
    pub streaming: StreamingConfig,
    pub did_resolver: DIDResolverConfig,
    pub limits: LimitsConfigRaw,
    pub processors: ProcessorsConfigRaw,
}

#[derive(Clone)]
pub struct Config {
    pub log_level: LevelFilter,
    pub listen_address: String,
    pub mediator_did: String,
    pub admin_did: String,
    pub mediator_secrets: AffinidiSecrets,
    pub database_url: String,
    pub database_pool_size: usize,
    pub database_timeout: u32,
    pub api_prefix: String,
    pub use_ssl: bool,
    pub ssl_certificate_file: String,
    pub ssl_key_file: String,
    pub jwt_encoding_key: Option<EncodingKey>,
    pub jwt_decoding_key: Option<DecodingKey>,
    pub streaming_enabled: bool,
    pub streaming_uuid: String,
    pub did_resolver_config: ClientConfig,
    pub cors_allow_origin: CorsLayer,
    pub process_forwarding: ForwardingConfig,
    pub limits: LimitsConfig,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("log_level", &self.log_level)
            .field("listen_address", &self.listen_address)
            .field("mediator_did", &self.mediator_did)
            .field("admin_did", &self.admin_did)
            .field("mediator_did_doc", &"Hidden")
            .field(
                "mediator_secrets",
                &format!("({}) secrets loaded", self.mediator_secrets.len()),
            )
            .field("use_ssl", &self.use_ssl)
            .field("cors_allow_origin", &self.cors_allow_origin)
            .field("database_url", &self.database_url)
            .field("database_pool_size", &self.database_pool_size)
            .field("database_timeout", &self.database_timeout)
            .field("ssl_certificate_file", &self.ssl_certificate_file)
            .field("ssl_key_file", &self.ssl_key_file)
            .field("jwt_encoding_key?", &self.jwt_encoding_key.is_some())
            .field("jwt_decoding_key?", &self.jwt_decoding_key.is_some())
            .field("streaming_enabled?", &self.streaming_enabled)
            .field("streaming_uuid", &self.streaming_uuid)
            .field("DID Resolver config", &self.did_resolver_config)
            .field("api_prefix", &self.api_prefix)
            .field("processor Forwarding", &self.process_forwarding)
            .field("Limits", &self.limits)
            .finish()
    }
}

impl Default for Config {
    fn default() -> Self {
        let did_resolver_config = ClientConfigBuilder::default()
            .with_cache_capacity(1000)
            .with_cache_ttl(300)
            .with_network_timeout(5)
            .with_network_cache_limit_count(100)
            .build();

        Config {
            log_level: LevelFilter::INFO,
            listen_address: "".into(),
            mediator_did: "".into(),
            admin_did: "".into(),
            mediator_secrets: AffinidiSecrets::new(vec![]),
            database_url: "redis://127.0.0.1/".into(),
            database_pool_size: 10,
            database_timeout: 2,
            use_ssl: true,
            ssl_certificate_file: "".into(),
            ssl_key_file: "".into(),
            jwt_encoding_key: None,
            jwt_decoding_key: None,
            streaming_enabled: true,
            streaming_uuid: "".into(),
            did_resolver_config,
            cors_allow_origin: CorsLayer::new().allow_origin(Any),
            api_prefix: "/mediator/v1/".into(),
            process_forwarding: ForwardingConfig::default(),
            limits: LimitsConfig::default(),
        }
    }
}

#[async_trait]
impl TryFrom<ConfigRaw> for Config {
    type Error = MediatorError;

    async fn try_from(raw: ConfigRaw) -> Result<Self, Self::Error> {
        // Set up AWS Configuration
        let region = match env::var("AWS_REGION") {
            Ok(region) => Region::new(region),
            Err(_) => Region::new("ap-southeast-1"),
        };
        let aws_config = aws_config::defaults(BehaviorVersion::v2024_03_28())
            .region(region)
            .load()
            .await;

        let mut config = Config {
            log_level: match raw.log_level.as_str() {
                "trace" => LevelFilter::TRACE,
                "debug" => LevelFilter::DEBUG,
                "info" => LevelFilter::INFO,
                "warn" => LevelFilter::WARN,
                "error" => LevelFilter::ERROR,
                _ => LevelFilter::INFO,
            },
            listen_address: raw.server.listen_address,
            mediator_did: read_did_config(&raw.mediator_did, &aws_config).await?,
            admin_did: read_did_config(&raw.server.admin_did, &aws_config).await?,
            database_url: raw.database.database_url,
            database_pool_size: raw.database.database_pool_size.parse().unwrap_or(10),
            database_timeout: raw.database.database_timeout.parse().unwrap_or(2),
            use_ssl: raw.security.use_ssl.parse().unwrap_or(true),
            ssl_certificate_file: raw.security.ssl_certificate_file,
            ssl_key_file: raw.security.ssl_key_file,
            streaming_enabled: raw.streaming.enabled.parse().unwrap_or(true),
            did_resolver_config: raw.did_resolver.convert(),
            api_prefix: raw.server.api_prefix,
            process_forwarding: raw.processors.forwarding.try_into()?,
            limits: raw.limits.try_into()?,
            ..Default::default()
        };

        if let Some(cors_allow_origin) = &raw.security.cors_allow_origin {
            config.cors_allow_origin =
                CorsLayer::new().allow_origin(parse_cors_allow_origin(cors_allow_origin)?);
        }

        // Load mediator secrets
        config.mediator_secrets = load_secrets(&raw.security.mediator_secrets, &aws_config).await?;

        // Create the JWT encoding and decoding keys
        let jwt_secret =
            config_jwt_secret(&raw.security.jwt_authorization_secret, &aws_config).await?;

        config.jwt_encoding_key = Some(EncodingKey::from_ed_der(&jwt_secret));

        let pair = Ed25519KeyPair::from_pkcs8(&jwt_secret).map_err(|err| {
            event!(Level::ERROR, "Could not create JWT key pair. {}", err);
            MediatorError::ConfigError(
                "NA".into(),
                format!("Could not create JWT key pair. {}", err),
            )
        })?;
        config.jwt_decoding_key = Some(DecodingKey::from_ed_der(pair.public_key().as_ref()));

        // Get Subscriber unique hostname
        if config.streaming_enabled {
            config.streaming_uuid = get_hostname(&raw.streaming.uuid)?;
        }

        Ok(config)
    }
}

fn parse_cors_allow_origin(cors_allow_origin: &str) -> Result<Vec<HeaderValue>, MediatorError> {
    let origins: Vec<HeaderValue> = cors_allow_origin
        .split(',')
        .map(|o| o.parse::<HeaderValue>().unwrap())
        .collect();

    Ok(origins)
}

/// Loads the secret data into the Config file.
async fn load_secrets(
    secrets: &str,
    aws_config: &SdkConfig,
) -> Result<AffinidiSecrets, MediatorError> {
    let parts: Vec<&str> = secrets.split("://").collect();
    if parts.len() != 2 {
        return Err(MediatorError::ConfigError(
            "NA".into(),
            "Invalid `mediator_secrets` format".into(),
        ));
    }
    info!("Loading secrets method({}) path({})", parts[0], parts[1]);
    let content: String = match parts[0] {
        "file" => read_file_lines(parts[1])?.concat(),
        "aws_secrets" => {
            let asm = aws_sdk_secretsmanager::Client::new(aws_config);

            let response = asm
                .get_secret_value()
                .secret_id(parts[1])
                .send()
                .await
                .map_err(|e| {
                    event!(Level::ERROR, "Could not get secret value. {}", e);
                    MediatorError::ConfigError(
                        "NA".into(),
                        format!("Could not get secret value. {}", e),
                    )
                })?;
            response.secret_string.ok_or_else(|| {
                event!(Level::ERROR, "No secret string found in response");
                MediatorError::ConfigError("NA".into(), "No secret string found in response".into())
            })?
        }
        _ => {
            return Err(MediatorError::ConfigError(
                "NA".into(),
                "Invalid `mediator_secrets` format! Expecting file:// or aws_secrets:// ...".into(),
            ))
        }
    };

    Ok(AffinidiSecrets::new(
        serde_json::from_str(&content).map_err(|err| {
            event!(
                Level::ERROR,
                "Could not parse `mediator_secrets` JSON content. {}",
                err
            );
            MediatorError::ConfigError(
                "NA".into(),
                format!("Could not parse `mediator_secrets` JSON content. {}", err),
            )
        })?,
    ))
}

/// Read the primary configuration file for the mediator
/// Returns a ConfigRaw struct, that still needs to be processed for additional information
/// and conversion to Config struct
fn read_config_file(file_name: &str) -> Result<ConfigRaw, MediatorError> {
    // Read configuration file parameters
    event!(Level::INFO, "Config file({})", file_name);
    let raw_config = read_file_lines(file_name)?;

    event!(Level::DEBUG, "raw_config = {:?}", raw_config);
    let config_with_vars = expand_env_vars(&raw_config)?;
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
/// ```ignore
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
fn expand_env_vars(raw_config: &Vec<String>) -> Result<Vec<String>, MediatorError> {
    let re = Regex::new(r"\$\{(?P<env_var>[A-Z_]{1,}[0-9A-Z_]*):(?P<default_value>.*)\}").map_err(
        |e| {
            MediatorError::ConfigError(
                "NA".into(),
                format!("Couldn't create ENV Regex. Reason: {}", e),
            )
        },
    )?;
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
    Ok(result)
}

/// Converts the mediator_did config to a valid DID depending on source
async fn read_did_config(
    did_config: &str,
    aws_config: &SdkConfig,
) -> Result<String, MediatorError> {
    let parts: Vec<&str> = did_config.split("://").collect();
    if parts.len() != 2 {
        return Err(MediatorError::ConfigError(
            "NA".into(),
            "Invalid `mediator_did` format".into(),
        ));
    }
    let content: String = match parts[0] {
        "did" => parts[1].to_string(),
        "aws_parameter_store" => {
            let ssm = aws_sdk_ssm::Client::new(aws_config);

            let response = ssm
                .get_parameter()
                .set_name(Some(parts[1].to_string()))
                .send()
                .await
                .map_err(|e| {
                    event!(Level::ERROR, "Could not get mediator_did parameter. {}", e);
                    MediatorError::ConfigError(
                        "NA".into(),
                        format!("Could not get mediator_did parameter. {}", e),
                    )
                })?;
            let parameter = response.parameter.ok_or_else(|| {
                event!(Level::ERROR, "No parameter string found in response");
                MediatorError::ConfigError(
                    "NA".into(),
                    "No parameter string found in response".into(),
                )
            })?;

            if let Some(_type) = parameter.r#type {
                if _type != ParameterType::String {
                    return Err(MediatorError::ConfigError(
                        "NA".into(),
                        "Expected String parameter type".into(),
                    ));
                }
            } else {
                return Err(MediatorError::ConfigError(
                    "NA".into(),
                    "Unknown parameter type".into(),
                ));
            }

            parameter.value.ok_or_else(|| {
                event!(
                    Level::ERROR,
                    "Parameter ({:?}) found, but no parameter value found in response",
                    parameter.name
                );
                MediatorError::ConfigError(
                    "NA".into(),
                    format!(
                        "Parameter ({:?}) found, but no parameter value found in response",
                        parameter.name
                    ),
                )
            })?
        }
        _ => {
            return Err(MediatorError::ConfigError(
                "NA".into(),
                "Invalid MEDIATOR_SECRETS format! Expecting file:// or aws_secrets:// ...".into(),
            ))
        }
    };

    Ok(content)
}

/// Converts the jwt_authorization_secret config to a valid JWT secret
/// Can take a basic string, or fetch from AWS Secrets Manager
async fn config_jwt_secret(
    jwt_secret: &str,
    aws_config: &SdkConfig,
) -> Result<Vec<u8>, MediatorError> {
    let parts: Vec<&str> = jwt_secret.split("://").collect();
    if parts.len() != 2 {
        return Err(MediatorError::ConfigError(
            "NA".into(),
            "Invalid `jwt_authorization_secret` format".into(),
        ));
    }
    let content: String = match parts[0] {
        "string" => parts[1].to_string(),
        "aws_secrets" => {
            info!("Loading JWT secret from AWS Secrets Manager");
            let asm = aws_sdk_secretsmanager::Client::new(aws_config);

            let response = asm
                .get_secret_value()
                .secret_id(parts[1])
                .send()
                .await
                .map_err(|e| {
                    event!(Level::ERROR, "Could not get secret value. {}", e);
                    MediatorError::ConfigError(
                        "NA".into(),
                        format!("Could not get secret value. {}", e),
                    )
                })?;
            response.secret_string.ok_or_else(|| {
                event!(Level::ERROR, "No secret string found in response");
                MediatorError::ConfigError("NA".into(), "No secret string found in response".into())
            })?
        }
        _ => return Err(MediatorError::ConfigError(
            "NA".into(),
            "Invalid `jwt_authorization_secret` format! Expecting string:// or aws_secrets:// ..."
                .into(),
        )),
    };

    BASE64_URL_SAFE_NO_PAD.decode(content).map_err(|err| {
        event!(Level::ERROR, "Could not create JWT key pair. {}", err);
        MediatorError::ConfigError(
            "NA".into(),
            format!("Could not create JWT key pair. {}", err),
        )
    })
}

fn get_hostname(host_name: &str) -> Result<String, MediatorError> {
    if host_name.starts_with("hostname://") {
        Ok(hostname::get()
            .map_err(|e| {
                MediatorError::ConfigError(
                    "NA".into(),
                    format!("Couldn't get hostname. Reason: {}", e),
                )
            })?
            .into_string()
            .map_err(|e| {
                MediatorError::ConfigError(
                    "NA".into(),
                    format!("Couldn't get hostname. Reason: {:?}", e),
                )
            })?)
    } else if host_name.starts_with("string://") {
        Ok(host_name.split_at(9).1.to_string())
    } else {
        Err(MediatorError::ConfigError(
            "NA".into(),
            "Invalid hostname format!".into(),
        ))
    }
}

pub async fn init(
    reload_handle: Option<Handle<EnvFilter, Registry>>,
) -> Result<Config, MediatorError> {
    // Read configuration file parameters
    let config = read_config_file("conf/mediator.toml")?;

    // Setup logging
    if reload_handle.is_some() {
        let level: EnvFilter = EnvFilter::new(config.log_level.as_str());
        reload_handle
            .unwrap()
            .modify(|filter| *filter = level)
            .map_err(|e| MediatorError::InternalError("NA".into(), e.to_string()))?;
        event!(Level::INFO, "Log level set to ({})", config.log_level);
    }

    match <Config as async_convert::TryFrom<ConfigRaw>>::try_from(config).await {
        Ok(config) => {
            event!(
                Level::INFO,
                "Configuration settings parsed successfully.\n{:#?}",
                config
            );
            Ok(config)
        }
        Err(err) => Err(err),
    }
}
