use crate::error::{Result, ToResult};
use serde::Deserialize;

use crate::{
    jwe::{envelope::Jwe, ParsedJWE},
    jws::{Jws, ParsedJWS},
    Message,
};

/// High level wrapper so we can serialize and deserialize the envelope types
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(crate) enum Envelope {
    Jwe(Jwe),
    Jws(Jws),
    Message(Message),
}

impl Envelope {
    pub fn from_str(s: &str) -> Result<Self> {
        serde_json::from_str(s).to_didcomm("Unable deserialize envelope")
    }

    pub fn parse(self) -> Result<ParsedEnvelope> {
        match self {
            Envelope::Jwe(jwe) => Ok(ParsedEnvelope::Jwe(jwe.parse()?)),
            Envelope::Jws(jws) => Ok(ParsedEnvelope::Jws(jws.parse()?)),
            Envelope::Message(msg) => Ok(ParsedEnvelope::Message(msg)),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum ParsedEnvelope {
    Jwe(ParsedJWE),
    Jws(ParsedJWS),
    Message(Message),
}

impl ParsedEnvelope {
    pub fn verify_didcomm(self) -> Result<Self> {
        match self {
            ParsedEnvelope::Jwe(jwe) => Ok(ParsedEnvelope::Jwe(jwe.verify_didcomm()?)),
            ParsedEnvelope::Jws(_) => Ok(self),
            ParsedEnvelope::Message(_) => Ok(self),
        }
    }
}
