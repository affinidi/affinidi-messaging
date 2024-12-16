use std::str::FromStr;

use crate::{
    error::{err_msg, Error, ErrorKind, Result, ToResult},
    secrets::SecretsResolver,
    utils::crypto::KnownKeyPair,
    UnpackMetadata,
};
use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use serde::Deserialize;
use sha256::digest;
use ssi::dids::Document;

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
impl FromStr for Envelope {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        serde_json::from_str(s).to_didcomm("Unable deserialize envelope")
    }
}

impl Envelope {
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

    pub fn get_type(&self) -> &str {
        match self {
            ParsedEnvelope::Jwe(_) => "JWE",
            ParsedEnvelope::Jws(_) => "JWS",
            ParsedEnvelope::Message(_) => "JMS",
        }
    }
}

/// Higher level Envelope that holds all required information pertaining to a DIDComm Message
#[derive(Debug, Default)]
pub struct MetaEnvelope {
    pub envelope: Option<Envelope>,              // The raw envelope
    pub parsed_envelope: Option<ParsedEnvelope>, // The parsed envelope
    pub metadata: UnpackMetadata,
    pub from_kid: Option<String>,       // Key ID of Sender
    pub from_did: Option<String>,       // DID of Sender (did:method:identifier)
    pub from_ddoc: Option<Document>,    // DID Document of Sender
    pub from_key: Option<KnownKeyPair>, // Key of Sender
    pub to_kid: Option<String>,
    pub to_did: Option<String>,
    pub to_kids_found: Vec<String>,
    pub sha256_hash: String,
}

impl MetaEnvelope {
    pub async fn new<S>(
        msg: &str,
        did_resolver: &DIDCacheClient,
        secrets_resolver: &S,
    ) -> Result<Self>
    where
        S: SecretsResolver + Send,
    {
        let mut envelope = Self::default();
        envelope.sha256_hash = digest(msg);
        envelope.envelope = Some(Envelope::from_str(msg)?);
        envelope.parsed_envelope = Some(
            envelope
                .envelope
                .as_ref()
                .unwrap()
                .parse()?
                .verify_didcomm()?,
        );

        envelope._from(did_resolver, secrets_resolver).await?;

        Ok(envelope)
    }

    async fn _from(
        &mut self,
        did_resolver: &DIDCacheClient,
        secrets_resolver: &dyn SecretsResolver,
    ) -> Result<&Self> {
        match self.parsed_envelope.as_ref() {
            Some(ParsedEnvelope::Jwe(jwe)) => {
                jwe.to_owned()
                    .fill_envelope_from(self, did_resolver, secrets_resolver)
                    .await?;
            }
            Some(ParsedEnvelope::Jws(_)) => {}
            Some(ParsedEnvelope::Message(_)) => {}
            _ => {
                return Err(err_msg(
                    ErrorKind::Malformed,
                    "Unable to fill envelope from",
                ))
            }
        };

        Ok(self)
    }
}
