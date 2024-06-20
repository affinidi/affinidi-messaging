use std::{str::FromStr, time::SystemTime};

use atn_atm_didcomm::{
    did::DIDResolver, secrets::SecretsResolver, Message, PackEncryptedMetadata,
    PackEncryptedOptions, UnpackMetadata,
};

use crate::common::errors::{MediatorError, Session};

use self::protocols::ping;

pub mod inbound;
pub mod protocols;

pub enum MessageType {
    TrustPing,            // Trust Ping Protocol
    AffinidiAuthenticate, // Affinidi Authentication Response
}

impl FromStr for MessageType {
    type Err = MediatorError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "https://didcomm.org/trust-ping/2.0/ping" => Ok(Self::TrustPing),
            "https://affinidi.com/atm/1.0/authenticate" => Ok(Self::AffinidiAuthenticate),
            _ => Err(MediatorError::ParseError(
                "-1".into(),
                s.into(),
                "Couldn't match on MessageType".into(),
            )),
        }
    }
}

impl MessageType {
    pub fn process(
        &self,
        message: &Message,
        session: &Session,
    ) -> Result<Option<Message>, MediatorError> {
        match self {
            Self::TrustPing => ping::process(message, session),
            Self::AffinidiAuthenticate => Err(MediatorError::NotImplemented(
                session.session_id.clone(),
                "Affinidi Authentication is only handled by the Authorization handler".into(),
            )),
        }
    }
}

pub(crate) trait MessageHandler {
    /// Processes an incoming message, determines any additional actions to take
    /// Returns a message to store and deliver if necessary
    fn process(&self, session: &Session) -> Result<Option<Message>, MediatorError>;

    /// Uses the incoming unpack metadata to determine best way to pack the message
    async fn pack<S, T>(
        &self,
        to_did: &str,
        mediator_did: &str,
        metadata: &UnpackMetadata,
        secrets_resolver: &S,
        did_resolver: &T,
    ) -> Result<(String, PackEncryptedMetadata), MediatorError>
    where
        S: SecretsResolver,
        T: DIDResolver;
}

impl MessageHandler for Message {
    fn process(&self, session: &Session) -> Result<Option<Message>, MediatorError> {
        let msg_type = self.type_.as_str().parse::<MessageType>()?;

        // Check if message expired
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if let Some(expires) = self.expires_time {
            if expires <= now {
                return Err(MediatorError::MessageExpired(
                    "-1".into(),
                    expires.to_string(),
                    now.to_string(),
                ));
            }
        }

        msg_type.process(self, session)
    }

    async fn pack<S, T>(
        &self,
        to_did: &str,
        mediator_did: &str,
        metadata: &UnpackMetadata,
        secrets_resolver: &S,
        did_resolver: &T,
    ) -> Result<(String, PackEncryptedMetadata), MediatorError>
    where
        S: SecretsResolver,
        T: DIDResolver,
    {
        if metadata.encrypted {
            // Respond with an encrypted message
            let a = match self
                .pack_encrypted(
                    to_did,
                    self.from.as_deref(),
                    Some(mediator_did),
                    did_resolver,
                    secrets_resolver,
                    &PackEncryptedOptions::default(),
                )
                .await
            {
                Ok(msg) => msg,
                Err(e) => {
                    return Err(MediatorError::MessagePackError("-1".into(), e.to_string()));
                }
            };

            Ok(a)
        } else {
            Err(MediatorError::MessagePackError(
                "-1".into(),
                "PACK METHOD NOT IMPLEMENTED".into(),
            ))
        }
    }
}
