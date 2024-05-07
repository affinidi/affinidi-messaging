use async_trait::async_trait;
use didcomm::{
    did::{DIDDoc, DIDResolver},
    error::Result,
};

#[derive(Clone)]
/// Allows resolve pre-defined did's for `example` and other methods.
pub struct AffinidiDIDResolver {
    known_dids: Vec<DIDDoc>,
}

impl AffinidiDIDResolver {
    pub fn new(known_dids: Vec<DIDDoc>) -> Self {
        AffinidiDIDResolver { known_dids }
    }
}

#[cfg_attr(feature = "uniffi", async_trait)]
#[cfg_attr(not(feature = "uniffi"), async_trait)]
impl DIDResolver for AffinidiDIDResolver {
    async fn resolve(&self, did: &str) -> Result<Option<DIDDoc>> {
        Ok(self.known_dids.iter().find(|ddoc| ddoc.id == did).cloned())
    }
}
