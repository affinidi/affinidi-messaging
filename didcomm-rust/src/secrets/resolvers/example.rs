use async_trait::async_trait;

use crate::{
    error::Result,
    secrets::{Secret, SecretsResolver},
};

pub struct ExampleSecretsResolver {
    known_secrets: Vec<Secret>,
}

impl ExampleSecretsResolver {
    pub fn new(known_secrets: Vec<Secret>) -> Self {
        ExampleSecretsResolver { known_secrets }
    }
}

#[cfg_attr(feature = "uniffi", async_trait)]
#[cfg_attr(not(feature = "uniffi"), async_trait)]
impl SecretsResolver for ExampleSecretsResolver {
    async fn get_secret(&self, secret_id: &str) -> Result<Option<Secret>> {
        Ok(self
            .known_secrets
            .iter()
            .find(|s| s.id == secret_id)
            .map(|s| s.clone()))
    }

    async fn find_secrets(&self, secret_ids: &Vec<String>) -> Result<Vec<String>> {
        Ok(secret_ids
            .iter()
            .filter(|sid| {
                self.known_secrets
                    .iter()
                    .find(|s| s.id == sid.to_string())
                    .is_some()
            })
            .map(|sid| sid.to_string())
            .collect())
    }
}
