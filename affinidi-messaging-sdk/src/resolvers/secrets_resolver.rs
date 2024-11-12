use std::sync::{Arc, Mutex};

use affinidi_messaging_didcomm::{
    error::Result,
    secrets::{Secret, SecretsResolver},
};
use async_trait::async_trait;
use tracing::debug;

#[derive(Clone, Debug)]
pub struct AffinidiSecrets {
    known_secrets: Arc<Mutex<Vec<Secret>>>,
}

impl AffinidiSecrets {
    pub fn new(known_secrets: Vec<Secret>) -> Self {
        AffinidiSecrets {
            known_secrets: Arc::new(Mutex::new(known_secrets)),
        }
    }

    pub fn insert(&self, secret: Secret) {
        debug!("Adding secret ({})", secret.id);
        self.known_secrets.lock().unwrap().push(secret);
    }

    pub fn len(&self) -> usize {
        self.known_secrets.lock().unwrap().len()
    }
}

#[async_trait]
impl SecretsResolver for AffinidiSecrets {
    async fn get_secret(&self, secret_id: &str) -> Result<Option<Secret>> {
        Ok(self
            .known_secrets
            .lock()
            .unwrap()
            .iter()
            .find(|s| s.id == secret_id)
            .cloned())
    }

    async fn find_secrets(&self, secret_ids: &[String]) -> Result<Vec<String>> {
        Ok(secret_ids
            .iter()
            .filter(|sid| {
                self.known_secrets
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|s| s.id == sid.to_string())
            })
            .cloned()
            .collect())
    }
}
