/*!
Profiles modules contains the implementation of the Profile struct and its methods.

For Profile network connections:
1. REST based API is stateless
2. WebSockets are managed via the WS_Handler task
*/

use crate::{
    errors::ATMError, messages::AuthorizationResponse, secrets::Secret,
    transports::websockets::ws_connection::WsConnectionCommands,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{mpsc::Sender, RwLock};

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
    pub alias: String,
    #[serde(skip)]
    pub(crate) rest_endpoint: Option<String>,
    #[serde(skip)]
    pub(crate) websocket_endpoint: Option<String>,
    #[serde(skip)]
    pub(crate) ws_enabled: bool,
    #[serde(skip)]
    pub(crate) ws_channel_tx: Option<Sender<WsConnectionCommands>>,
}

/// Key is the alias of the profile
/// If no alias is provided, the DID is used as the key
#[derive(Default)]
pub struct Profiles(HashMap<String, Arc<RwLock<Profile>>>);

impl Profiles {
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
