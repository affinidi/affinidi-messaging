use base64::prelude::*;
use sha2::{Digest, Sha256};

use crate::error::ToResult;
use crate::{
    error::{err_msg, ErrorKind, Result, ResultExt},
    jwe::envelope::{ProtectedHeader, JWE},
};

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ParsedJWE {
    pub(crate) jwe: JWE,
    pub(crate) protected: ProtectedHeader,
    pub(crate) apu: Option<Vec<u8>>,
    pub(crate) apv: Vec<u8>,
    pub(crate) to_kids: Vec<String>,
}

pub(crate) fn parse(jwe: &str) -> Result<ParsedJWE> {
    JWE::from_str(jwe)?.parse()
}

impl JWE {
    pub(crate) fn from_str(s: &str) -> Result<JWE> {
        serde_json::from_str(s).to_didcomm("Unable parse jwe")
    }

    pub(crate) fn parse(self) -> Result<ParsedJWE> {
        let decoded = BASE64_URL_SAFE_NO_PAD
            .decode(self.protected.clone())
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

        if &self.apv != did_comm_apv.as_slice() {
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
}
