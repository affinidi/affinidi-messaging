/*!
Profiles modules contains the implementation of the Profile struct and its methods.

For Profile network connections:
1. REST based API is stateless
2. WebSockets are managed via the WS_Handler task
*/

use crate::{
    errors::ATMError,
    messages::AuthorizationResponse,
    transports::websockets::{ws_connection::WsConnectionCommands, ws_handler::WsHandlerCommands},
    ATM,
};
use affinidi_messaging_didcomm::secrets::Secret;
use serde::{Deserialize, Serialize};
use ssi::dids::{
    document::{service::Endpoint, Service},
    Document,
};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{mpsc::Sender, RwLock};
use tracing::debug;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Profile {
    pub did: String,
    pub alias: String,
    #[serde(skip)]
    pub secrets: Vec<Secret>,
    pub mediator: Option<Mediator>,
    #[serde(skip)]
    pub(crate) authorization: Option<AuthorizationResponse>,
    #[serde(skip)]
    pub(crate) authenticated: bool,
}

impl Profile {
    /// Creates a new Profile
    /// If no alias is provided, the DID is used as the alias
    /// If no mediator is provided, the mediator field will default the Default Mediator if provided
    /// If no mediator and no default mediator is provided, the mediator field will be None (which is unlikely to be useful)
    pub async fn new(
        atm: &ATM,
        alias: Option<String>,
        did: String,
        mediator: Option<String>,
        secrets: Vec<Secret>,
    ) -> Result<Self, ATMError> {
        let alias = if let Some(alias) = alias {
            alias.clone()
        } else {
            did.clone()
        };

        let mediator = if let Some(mediator) = mediator {
            Mediator::new(atm, mediator).await.ok()
        } else {
            None
        };

        println!("Mediator: {:?}", mediator);

        let profile = Profile {
            did,
            alias,
            secrets,
            mediator,
            authorization: None,
            authenticated: false,
        };

        Ok(profile)
    }

    /// Returns the DID for the Profile and Associated Mediator
    /// Will return an error if no Mediator
    /// Returns Ok(profile_did, mediator_did)
    pub fn dids(&self) -> Result<(&str, &str), ATMError> {
        let Some(mediator) = &self.mediator else {
            return Err(ATMError::ConfigError(
                "No Mediator is configured for this Profile".to_string(),
            ));
        };

        Ok((&self.did, &mediator.did))
    }

    /// Return the REST endpoint for this profile if it exists
    pub fn get_mediator_rest_endpoint(&self) -> Option<String> {
        if let Some(mediator) = &self.mediator {
            mediator.rest_endpoint.clone()
        } else {
            None
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Mediator {
    pub did: String,
    #[serde(skip)]
    pub(crate) rest_endpoint: Option<String>,
    #[serde(skip)]
    pub(crate) websocket_endpoint: Option<String>,
    #[serde(skip)]
    pub(crate) ws_connected: bool, // Whether the websocket is connected
    #[serde(skip)]
    pub(crate) ws_channel_tx: Option<Sender<WsConnectionCommands>>,
}

impl Mediator {
    pub(crate) async fn new(atm: &ATM, did: String) -> Result<Self, ATMError> {
        let mediator_doc = match atm.inner.did_resolver.resolve(&did).await {
            Ok(response) => response.doc,
            Err(err) => {
                return Err(ATMError::DIDError(format!(
                    "Couldn't resolve DID ({}). Reason: {}",
                    did, err
                )));
            }
        };

        let mediator = Mediator {
            did,
            rest_endpoint: Mediator::find_rest_endpoint(&mediator_doc),
            websocket_endpoint: Mediator::find_ws_endpoint(&mediator_doc),
            ws_connected: false,
            ws_channel_tx: None,
        };

        Ok(mediator)
    }

    /// Helper function to find the endpoint for the Mediator
    /// protocol allows you to specify the URI scheme (http, ws, etc)
    fn _find_endpoint(service: &Service, protocol: &str) -> Option<String> {
        if service.type_.contains(&"DIDCommMessaging".to_string()) {
            if let Some(endpoint) = &service.service_endpoint {
                for endpoint in endpoint.into_iter() {
                    match endpoint {
                        Endpoint::Map(map) => {
                            if let Some(accept) = map.get("accept") {
                                let accept: Vec<String> =
                                    match serde_json::from_value(accept.to_owned()) {
                                        Ok(accept) => accept,
                                        Err(_) => continue,
                                    };

                                if accept.contains(&"didcomm/v2".to_string()) {
                                    if let Some(uri) = map.get("uri") {
                                        if let Some(uri) = uri.as_str() {
                                            if uri.starts_with(protocol) {
                                                return Some(uri.to_string());
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        _ => {
                            // Ignore URI}
                        }
                    }
                }
            }
        }

        None
    }

    /// Finds the REST endpoint for the Mediator if it exists
    fn find_rest_endpoint(doc: &Document) -> Option<String> {
        for service in doc.service.iter() {
            if let Some(endpoint) = Mediator::_find_endpoint(service, "http") {
                return Some(endpoint);
            }
        }

        None
    }

    /// Finds the WebSocket endpoint for the Mediator if it exists
    fn find_ws_endpoint(doc: &Document) -> Option<String> {
        for service in doc.service.iter() {
            if let Some(endpoint) = Mediator::_find_endpoint(service, "ws") {
                return Some(endpoint);
            }
        }

        None
    }
}

/// Key is the alias of the profile
/// If no alias is provided, the DID is used as the key
#[derive(Default)]
pub struct Profiles(HashMap<String, Arc<RwLock<Profile>>>);

impl Profiles {
    pub fn insert(&mut self, profile: Profile) -> Option<Arc<RwLock<Profile>>> {
        self.0
            .insert(profile.alias.clone(), Arc::new(RwLock::new(profile)))
    }

    pub fn get(&self, key: &str) -> Option<Arc<RwLock<Profile>>> {
        self.0.get(key).cloned()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl ATM {
    /// Adds a profile to the ATM instance
    /// Returns None if the profile is new
    /// Returns Some(profile) if the profile already exists
    ///   NOTE: It will have replaced the old profile with the new one
    /// Inputs:
    ///   profile: Profile - DID and Mediator information
    ///   live_stream: bool - If true, then start websocket connection and live_streaming
    pub async fn profile_add(
        &self,
        profile: &Profile,
        live_stream: bool,
    ) -> Result<Option<Arc<RwLock<Profile>>>, ATMError> {
        let _insert = self.inner.profiles.write().await.insert(profile.clone());

        // Add the profile secrets to Secrets Manager
        self.add_secrets(&profile.secrets).await;

        if live_stream {
            // Grab a copy of the wrapped Profile
            if let Some(profile) = self.inner.profiles.read().await.get(&profile.alias) {
                self.profile_enable_websocket(&profile).await?;
            }
        }
        Ok(_insert)
    }

    /// Will create a websocket connection for the profile if one doesn't already exist
    /// Will return Ok() if a connection already exists, or if it successfully started a new connection
    pub async fn profile_enable_websocket(
        &self,
        profile: &Arc<RwLock<Profile>>,
    ) -> Result<(), ATMError> {
        let Some(mediator) = &profile.read().await.mediator else {
            return Err(ATMError::ConfigError(
                "No Mediator is configured for this Profile".to_string(),
            ));
        };

        if mediator.ws_connected {
            // Already connected
            debug!(
                "Profile ({}): is already connected to the WebSocket",
                profile.read().await.alias
            );
            return Ok(());
        }

        debug!("Profile({}): enabling...", profile.read().await.alias);

        // Send this profile info to the WS_Handler
        let a = self
            .inner
            .ws_handler_send_stream
            .send(WsHandlerCommands::Activate(profile.clone()))
            .await;

        Ok(())
    }
}
