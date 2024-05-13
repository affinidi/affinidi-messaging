use async_trait::async_trait;

use didcomm::{
    error::Result,
    secrets::{Secret, SecretsResolver},
};

#[derive(Clone)]
pub struct AffinidiSecrets {
    known_secrets: Vec<Secret>,
}

impl AffinidiSecrets {
    pub fn new(known_secrets: Vec<Secret>) -> Self {
        AffinidiSecrets { known_secrets }
    }

    pub fn len(&self) -> usize {
        self.known_secrets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.known_secrets.is_empty()
    }
}

#[cfg_attr(feature = "uniffi", async_trait)]
#[cfg_attr(not(feature = "uniffi"), async_trait)]
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
