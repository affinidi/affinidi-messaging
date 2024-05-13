use crate::did::DIDResolver;
use crate::envelope::ParsedEnvelope;
use crate::error::Result;
use crate::{FromPrior, Message, UnpackMetadata};

pub(crate) async fn _try_unpack_plaintext(
    msg: &ParsedEnvelope,
    did_resolver: &dyn DIDResolver,
    metadata: &mut UnpackMetadata,
) -> Result<Option<Message>> {
    let msg = match msg {
        ParsedEnvelope::Message(msg) => msg.clone().validate()?,
        _ => return Ok(None),
    };

    if let Some(from_prior) = &msg.from_prior {
        let (unpacked_from_prior, from_prior_issuer_kid) =
            FromPrior::unpack(from_prior, did_resolver).await?;

        metadata.from_prior = Some(unpacked_from_prior);
        metadata.from_prior_issuer_kid = Some(from_prior_issuer_kid);
    };

    Ok(Some(msg))
}
