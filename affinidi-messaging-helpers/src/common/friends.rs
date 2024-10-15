use affinidi_messaging_didcomm::secrets::Secret;
use serde::{Deserialize, Serialize};
use std::error::Error;

use super::did::create_did;

/// Friends are actors in examples that help showcase functionality
/// They have a name, a DID, and a set of keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Friend {
    pub name: String,
    pub did: String,
    pub keys: Vec<Secret>,
}

impl Friend {
    pub fn new(name: &str, service: Option<String>) -> Result<Self, Box<dyn Error>> {
        let did = create_did(service)?;

        Ok(Self {
            name: name.to_string(),
            did: did.0,
            keys: did.1,
        })
    }
}
