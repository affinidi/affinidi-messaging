use atn_atm_didcomm::{envelope::MetaEnvelope, Message, UnpackMetadata, UnpackOptions};
use tracing::{debug, span, Level};

use crate::{errors::ATMError, ATM};

impl<'c> ATM<'c> {
    pub async fn unpack(&mut self, message: &str) -> Result<(Message, UnpackMetadata), ATMError> {
        let _span = span!(Level::DEBUG, "unpack",).entered();

        let mut envelope = match MetaEnvelope::new(
            message,
            &mut self.did_resolver,
            &self.secrets_resolver,
            &self.did_methods_resolver,
        )
        .await
        {
            Ok(envelope) => envelope,
            Err(e) => {
                return Err(ATMError::DidcommError(
                    "Cannot convert string to MetaEnvelope".into(),
                    e.to_string(),
                ));
            }
        };
        debug!("message converted to MetaEnvelope");

        // Unpack the message
        let (msg, metadata) = match Message::unpack(
            &mut envelope,
            &mut self.did_resolver,
            &self.did_methods_resolver,
            &self.secrets_resolver,
            &UnpackOptions::default(),
        )
        .await
        {
            Ok(ok) => ok,
            Err(e) => {
                return Err(ATMError::DidcommError(
                    "Couldn't unpack incoming message".into(),
                    e.to_string(),
                ));
            }
        };

        debug!("message unpacked:\n{:#?}", msg);
        Ok((msg, metadata))
    }
}
