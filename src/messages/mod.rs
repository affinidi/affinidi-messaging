use std::{str::FromStr, time::SystemTime};

use didcomm::Message;

use crate::common::errors::{MediatorError, Session};

use self::protocols::ping;

pub mod protocols;

pub enum MessageType {
    Ping,
}

impl FromStr for MessageType {
    type Err = MediatorError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "https://didcomm.org/trust-ping/2.0/ping" => Ok(Self::Ping),
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
            Self::Ping => ping::process(message, session),
        }
    }
}

pub trait MessageHandler {
    fn process(&self, session: &Session) -> Result<Option<Message>, MediatorError>;
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
}
