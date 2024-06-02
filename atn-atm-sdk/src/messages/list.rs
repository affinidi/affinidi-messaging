use crate::{errors::ATMError, ATM};
use std::fmt::Display;
use tracing::{debug, span, Level};

pub enum Folder {
    Inbox,
    Outbox,
}

impl Display for Folder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Folder::Inbox => write!(f, "inbox"),
            Folder::Outbox => write!(f, "outbox"),
        }
    }
}

impl<'c> ATM<'c> {
    /// Returns a list of messages that are stored in the ATM
    pub async fn list_messages(&mut self, to_did: &str, folder: Folder) -> Result<(), ATMError> {
        let _span = span!(Level::DEBUG, "list_messages", folder = folder.to_string()).entered();
        debug!("listing folder({}) for DID({})", to_did, folder);

        // Check that DID exists in DIDResolver, add it if not
        if !self.did_resolver.contains(to_did) {
            debug!("DID not found in resolver, adding...");
            self.add_did(to_did).await?;
        }

        // Check if authenticated
        let tokens = self.authenticate().await?;

        let res = self
            .client
            .get(format!("{}/list/{}", self.config.atm_api, folder))
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", tokens.access_token))
            .send()
            .await
            .map_err(|e| {
                ATMError::HTTPSError(format!("Could not send list_messages request: {:?}", e))
            })?;

        let status = res.status();
        debug!("API response: status({})", status);

        let body = res
            .text()
            .await
            .map_err(|e| ATMError::HTTPSError(format!("Couldn't get body: {:?}", e)))?;

        if !status.is_success() {
            debug!("Failed to get response body. Body: {:?}", body);
        }
        /*
        let body = serde_json::from_str::<SuccessResponse<T>>(&body)
            .ok()
            .unwrap();
        */

        Ok(())
    }
}
