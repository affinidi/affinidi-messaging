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

    async fn find_secrets<'a>(&self, secret_ids: &'a [&'a str]) -> Result<Vec<&'a str>> {
        Ok(secret_ids
            .iter()
            .filter(|&&sid| self.known_secrets.iter().any(|s| s.id == sid))
            .cloned()
            .collect())
    }
}
