use affinidi_messaging_didcomm::{
    error::Result,
    secrets::{Secret, SecretsResolver},
};
use async_trait::async_trait;
use tracing::debug;

#[derive(Clone, Debug)]
pub struct AffinidiSecrets {
    known_secrets: Vec<Secret>,
}

impl AffinidiSecrets {
    pub fn new(known_secrets: Vec<Secret>) -> Self {
        AffinidiSecrets { known_secrets }
    }

    pub fn insert(&mut self, secret: Secret) {
        debug!("Adding secret ({})", secret.id);
        self.known_secrets.push(secret);
    }

    pub fn len(&self) -> usize {
        self.known_secrets.len()
    }
}

#[async_trait]
impl SecretsResolver for AffinidiSecrets {
    async fn get_secret(&self, secret_id: &str) -> Result<Option<Secret>> {
        Ok(self
            .known_secrets
            .iter()
            .find(|s| s.id == secret_id)
            .cloned())
    }

    async fn find_secrets(&self, secret_ids: &[String]) -> Result<Vec<String>> {
        Ok(secret_ids
            .iter()
            .filter(|sid| self.known_secrets.iter().any(|s| s.id == sid.to_string()))
            .cloned()
            .collect())
    }
}
