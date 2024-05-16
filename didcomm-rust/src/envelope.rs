use crate::{
    did::{DIDDoc, DIDResolver},
    error::{err_msg, ErrorKind, Result, ToResult},
    utils::crypto::KnownKeyPair,
    UnpackMetadata,
};
use serde::Deserialize;
use ssi::did::DIDMethods;

use crate::{
    jwe::{envelope::Jwe, ParsedJWE},
    jws::{Jws, ParsedJWS},
    Message,
};

/// High level wrapper so we can serialize and deserialize the envelope types
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum Envelope {
    Jwe(Jwe),
    Jws(Jws),
    Message(Message),
}

impl Envelope {
    pub fn from_str(s: &str) -> Result<Self> {
        serde_json::from_str(s).to_didcomm("Unable deserialize envelope")
    }

    pub fn parse(&self) -> Result<ParsedEnvelope> {
        match self {
            Envelope::Jwe(jwe) => Ok(ParsedEnvelope::Jwe(jwe.to_owned().parse()?)),
            Envelope::Jws(jws) => Ok(ParsedEnvelope::Jws(jws.parse()?)),
            Envelope::Message(msg) => Ok(ParsedEnvelope::Message(msg.to_owned())),
        }
    }
}

#[derive(Debug, Clone)]
pub enum ParsedEnvelope {
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

/// Higher level Envelope that holds all required information pertaining to a DIDComm Message
#[derive(Debug)]
pub struct MetaEnvelope {
    pub envelope: Option<Envelope>,              // The raw envelope
    pub parsed_envelope: Option<ParsedEnvelope>, // The parsed envelope
    pub metadata: UnpackMetadata,
    pub from_kid: Option<String>,       // Key ID of Sender
    pub from_did: Option<String>,       // DID of Sender (did:method:identifier)
    pub from_ddoc: Option<DIDDoc>,      // DID Document of Sender
    pub from_key: Option<KnownKeyPair>, // Key of Sender
}

impl Default for MetaEnvelope {
    fn default() -> Self {
        Self {
            envelope: None,
            parsed_envelope: None,
            metadata: UnpackMetadata::default(),
            from_kid: None,
            from_did: None,
            from_ddoc: None,
            from_key: None,
        }
    }
}

impl MetaEnvelope {
    pub async fn new<T>(
        msg: &str,
        did_resolver: &mut T,
        did_methods: &DIDMethods<'_>,
    ) -> Result<Self>
    where
        T: DIDResolver,
    {
        let mut envelope = Self::default();
        envelope.envelope = Some(Envelope::from_str(msg)?);
        envelope.parsed_envelope = Some(
            envelope
                .envelope
                .as_ref()
                .unwrap()
                .parse()?
                .verify_didcomm()?,
        );

        envelope._from(did_resolver, did_methods).await?;

        Ok(envelope)
    }

    async fn _from(
        &mut self,
        did_resolver: &mut dyn DIDResolver,
        did_methods: &DIDMethods<'_>,
    ) -> Result<&Self> {
        let jwe = match self.parsed_envelope.as_ref() {
            Some(ParsedEnvelope::Jwe(jwe)) => jwe,
            _ => {
                return Err(err_msg(
                    ErrorKind::Malformed,
                    "Unable to fill envelope from",
                ))
            }
        };

        jwe.to_owned()
            .fill_envelope_from(self, did_resolver, did_methods)
            .await?;

        Ok(self)
    }
}
