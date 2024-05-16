use crate::envelope::MetaEnvelope;
use crate::error::ToResult;
use crate::utils::crypto::AsKnownKeyPair;
use crate::utils::did::did_or_url;
use crate::utils::did_conversion::convert_did;
use crate::{
    error::{err_msg, ErrorKind, Result, ResultExt},
    jwe::envelope::{Jwe, ProtectedHeader},
};
use base64::prelude::*;
use did_peer::DIDPeer;
use sha2::{Digest, Sha256};
use ssi::did::DIDMethods;
use ssi::did_resolve::DIDResolver;
use ssi::did_resolve::ResolutionInputMetadata;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedJWE {
    pub jwe: Jwe,
    pub protected: ProtectedHeader,
    pub apu: Option<Vec<u8>>,
    pub apv: Vec<u8>,
    pub to_kids: Vec<String>,
}

pub fn parse(jwe: &str) -> Result<ParsedJWE> {
    Jwe::from_str(jwe)?.parse()
}

impl Jwe {
    pub(crate) fn from_str(s: &str) -> Result<Jwe> {
        serde_json::from_str(s).to_didcomm("Unable parse jwe")
    }

    pub(crate) fn parse(self) -> Result<ParsedJWE> {
        // Strip off base64 padding
        let decoded = BASE64_URL_SAFE_NO_PAD
            .decode(self.protected.replace('=', ""))
            .kind(ErrorKind::Malformed, "Unable decode protected header")?;

        let protected: ProtectedHeader =
            serde_json::from_slice(&decoded).to_didcomm("Unable parse protected header")?;

        let apv = BASE64_URL_SAFE_NO_PAD
            .decode(protected.apv.clone())
            .kind(ErrorKind::Malformed, "Unable decode apv")?;

        let apu = protected
            .apu
            .as_ref()
            .map(|apu| BASE64_URL_SAFE_NO_PAD.decode(apu))
            .transpose()
            .kind(ErrorKind::Malformed, "Unable decode apu")?;

        let to_kids = self
            .recipients
            .clone()
            .iter()
            .map(|r| r.header.kid.clone())
            .collect();
        let jwe = ParsedJWE {
            jwe: self,
            protected,
            apu,
            apv,
            to_kids,
        };

        Ok(jwe)
    }
}

impl ParsedJWE {
    /// Verifies that apv and apu filled according DID Comm specification.
    pub(crate) fn verify_didcomm(self) -> Result<Self> {
        let did_comm_apv = {
            let mut kids = self
                .jwe
                .recipients
                .iter()
                .map(|r| r.header.kid.clone())
                .collect::<Vec<_>>();

            kids.sort();
            Sha256::digest(kids.join(".").as_bytes())
        };

        if self.apv != did_comm_apv.as_slice() {
            Err(err_msg(ErrorKind::Malformed, "APV mismatch"))?;
        }

        let did_comm_apu = self
            .apu
            .as_deref()
            .map(std::str::from_utf8)
            .transpose()
            .kind(ErrorKind::Malformed, "Invalid utf8 for apu")?;

        match (did_comm_apu, self.protected.skid.clone()) {
            (Some(apu), Some(skid)) if apu != skid => {
                Err(err_msg(ErrorKind::Malformed, "APU mismatch"))?
            }
            (None, Some(_)) => Err(err_msg(ErrorKind::Malformed, "SKID present, but no apu"))?,
            _ => (),
        };

        Ok(self)
    }

    /// Populates various from_* fields for the Envelope
    pub async fn fill_envelope_from(
        &self,
        envelope: &mut MetaEnvelope,
        did_resolver: &mut dyn crate::did::DIDResolver,
        did_methods: &DIDMethods<'_>,
    ) -> Result<&Self> {
        let from_kid = std::str::from_utf8(
            self.apu
                .as_deref()
                .ok_or_else(|| err_msg(ErrorKind::Malformed, "No apu presented for JWE"))?,
        )
        .kind(ErrorKind::Malformed, "apu is invalid utf8")?;

        let (from_did, from_url) = did_or_url(from_kid);

        if from_url.is_none() {
            Err(err_msg(
                ErrorKind::Malformed,
                "Sender key can't be resolved to key agreement",
            ))?;
        }

        envelope.from_did = Some(from_did.into());

        let (_, doc_opt, _) = did_methods
            .resolve(
                envelope.from_did.as_ref().unwrap(),
                &ResolutionInputMetadata::default(),
            )
            .await;

        let doc = doc_opt.ok_or_else(|| {
            err_msg(
                ErrorKind::Malformed,
                format!(
                    "Could not resolve senders DID ({})",
                    envelope.from_did.as_ref().unwrap()
                ),
            )
        })?;

        let doc = if let Ok(doc) = DIDPeer::expand_keys(&doc).await {
            doc
        } else {
            return Err(err_msg(
                ErrorKind::Malformed,
                format!(
                    "Could not resolve senders DID ({})",
                    envelope.from_did.as_ref().unwrap()
                ),
            ));
        };

        envelope.from_ddoc = match convert_did(&doc) {
            Ok(ddoc) => Some(ddoc),
            Err(e) => {
                return Err(err_msg(
                    ErrorKind::DIDNotResolved,
                    format!("Couldn't convert DID. Reason: {}", e),
                ));
            }
        };

        // Add the Document to the list of DID Documents
        did_resolver.insert(envelope.from_ddoc.as_ref().unwrap());

        envelope.from_kid = Some(
            envelope
                .from_ddoc
                .as_ref()
                .unwrap()
                .key_agreement
                .iter()
                .find(|&k| k.as_str() == from_kid)
                .ok_or_else(|| err_msg(ErrorKind::DIDUrlNotFound, "Sender kid not found in did"))?
                .to_string(),
        );

        envelope.from_key = Some(
            envelope
                .from_ddoc
                .as_ref()
                .unwrap()
                .verification_method
                .iter()
                .find(|&vm| &vm.id == from_kid)
                .ok_or_else(|| {
                    err_msg(
                        ErrorKind::DIDUrlNotFound,
                        "Sender verification method not found in did",
                    )
                })?
                .as_key_pair()?,
        );

        Ok(self)
    }
}
