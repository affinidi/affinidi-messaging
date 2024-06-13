use async_trait::async_trait;

use crate::{
    did::{DIDDoc, DIDResolver},
    error::Result,
};

/// Allows resolve pre-defined did's for `example` and other methods.
pub struct ExampleDIDResolver {
    known_dids: Vec<DIDDoc>,
}

impl ExampleDIDResolver {
    pub fn new(known_dids: Vec<DIDDoc>) -> Self {
        ExampleDIDResolver { known_dids }
    }
}

#[cfg_attr(feature = "uniffi", async_trait)]
#[cfg_attr(not(feature = "uniffi"), async_trait)]
impl DIDResolver for ExampleDIDResolver {
    async fn resolve(&self, did: &str) -> Result<Option<DIDDoc>> {
        Ok(self.known_dids.iter().find(|ddoc| ddoc.id == did).cloned())
    }

    fn insert(&mut self, did_doc: &DIDDoc) {
        self.known_dids.push(did_doc.clone());
    }
}