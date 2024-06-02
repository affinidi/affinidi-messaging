use std::collections::HashMap;

use async_trait::async_trait;
use atn_atm_didcomm::{
    did::{DIDDoc, DIDResolver},
    error::Result,
};

#[derive(Clone)]
/// Allows resolve pre-defined did's for `example` and other methods.
pub struct AffinidiDIDResolver {
    pub known_dids: HashMap<String, DIDDoc>,
}

impl AffinidiDIDResolver {
    pub fn new(dids: Vec<DIDDoc>) -> Self {
        let mut known_dids = HashMap::new();
        for did in &dids {
            known_dids.insert(did.id.clone(), did.clone());
        }
        AffinidiDIDResolver { known_dids }
    }

    pub fn contains(&mut self, did: &str) -> bool {
        self.known_dids.contains_key(did)
    }
}

#[async_trait]
impl DIDResolver for AffinidiDIDResolver {
    async fn resolve(&self, did: &str) -> Result<Option<DIDDoc>> {
        Ok(self.known_dids.get(did).cloned())
    }

    fn insert(&mut self, did_doc: &DIDDoc) {
        self.known_dids.insert(did_doc.id.clone(), did_doc.clone());
    }
}
