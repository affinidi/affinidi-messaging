use askar_crypto::{
    alg::{
        aes::{A256CbcHs512, A256Kw, AesKey},
        k256::K256KeyPair,
        p256::P256KeyPair,
        x25519::X25519KeyPair,
    },
    kdf::ecdh_1pu::Ecdh1PU,
};
use atn_did_cache_sdk::DIDCacheClient;
use std::str::FromStr;
use tracing::{debug, event, Level};

use crate::envelope::{Envelope, MetaEnvelope, ParsedEnvelope};
use crate::{
    algorithms::AuthCryptAlg,
    error::{err_msg, ErrorKind, Result, ResultExt},
    jwe,
    secrets::SecretsResolver,
    utils::crypto::{AsKnownKeyPairSecret, KnownKeyPair},
    UnpackOptions,
};

pub(crate) async fn _try_unpack_authcrypt(
    jwe: &ParsedEnvelope,
    did_resolver: &DIDCacheClient,
    secrets_resolver: &dyn SecretsResolver,
    opts: &UnpackOptions,
    envelope: &mut MetaEnvelope,
) -> Result<Option<ParsedEnvelope>> {
    let jwe = match jwe {
        ParsedEnvelope::Jwe(jwe) => jwe,
        _ => return Ok(None),
    };

    event!(
        Level::DEBUG,
        "expecting (ECDH-1PU+A256KW) jwe.protected.alg({})",
        jwe.protected.alg
    );
    if jwe.protected.alg != jwe::Algorithm::Ecdh1puA256kw {
        return Ok(None);
    }

    if jwe.apu.is_some() && envelope.from_kid.is_none() {
        debug!("Recalculating envelope meta-data from APU");
        jwe.fill_envelope_from(envelope, did_resolver, secrets_resolver)
            .await?;
    }

    let mut payload: Option<Vec<u8>> = None;

    debug!("{} to_kids found", &envelope.to_kids_found.len());
    for to_kid in &envelope.to_kids_found {
        let to_key = secrets_resolver.get_secret(to_kid).await?.ok_or_else(|| {
            err_msg(
                ErrorKind::InvalidState,
                "Recipient secret not found after existence checking",
            )
        })?;
        let to_key = to_key.as_key_pair()?;

        let _payload = match (
            envelope.from_key.as_ref().unwrap(),
            &to_key,
            &jwe.protected.enc,
        ) {
            (
                KnownKeyPair::X25519(ref from_key),
                KnownKeyPair::X25519(ref to_key),
                jwe::EncAlgorithm::A256cbcHs512,
            ) => {
                envelope.metadata.enc_alg_auth = Some(AuthCryptAlg::A256cbcHs512Ecdh1puA256kw);

                jwe.decrypt::<
                    AesKey<A256CbcHs512>,
                    Ecdh1PU<'_, X25519KeyPair>,
                    X25519KeyPair,
                    AesKey<A256Kw>,
                >(Some((envelope.from_kid.as_ref().unwrap(), from_key)), (to_kid, to_key))?
            }
            (
                KnownKeyPair::P256(ref from_key),
                KnownKeyPair::P256(ref to_key),
                jwe::EncAlgorithm::A256cbcHs512,
            ) => {
                envelope.metadata.enc_alg_auth = Some(AuthCryptAlg::A256cbcHs512Ecdh1puA256kw);

                jwe.decrypt::<
                    AesKey<A256CbcHs512>,
                    Ecdh1PU<'_, P256KeyPair>,
                    P256KeyPair,
                    AesKey<A256Kw>,
                >(Some((envelope.from_kid.as_ref().unwrap(), from_key)), (to_kid, to_key))?
            }
            (KnownKeyPair::X25519(_), KnownKeyPair::P256(_), _) => Err(err_msg(
                ErrorKind::Malformed,
                "Incompatible sender and recipient key agreement curves",
            ))?,
            (KnownKeyPair::P256(_), KnownKeyPair::X25519(_), _) => Err(err_msg(
                ErrorKind::Malformed,
                "Incompatible sender and recipient key agreement curves",
            ))?,
            (
                KnownKeyPair::K256(ref from_key),
                KnownKeyPair::K256(ref to_key),
                jwe::EncAlgorithm::A256cbcHs512,
            ) => {
                envelope.metadata.enc_alg_auth = Some(AuthCryptAlg::A256cbcHs512Ecdh1puA256kw);

                jwe.decrypt::<
                    AesKey<A256CbcHs512>,
                    Ecdh1PU<'_, K256KeyPair>,
                    K256KeyPair,
                    AesKey<A256Kw>,
                >(Some((envelope.from_kid.as_ref().unwrap(), from_key)), (to_kid, to_key))?
            }
            (KnownKeyPair::X25519(_), KnownKeyPair::K256(_), _) => Err(err_msg(
                ErrorKind::Malformed,
                "Incompatible sender and recipient key agreement curves",
            ))?,
            (KnownKeyPair::K256(_), KnownKeyPair::X25519(_), _) => Err(err_msg(
                ErrorKind::Malformed,
                "Incompatible sender and recipient key agreement curves",
            ))?,
            _ => Err(err_msg(
                ErrorKind::Unsupported,
                "Unsupported key agreement method",
            ))?,
        };

        payload = Some(_payload);

        if !opts.expect_decrypt_by_all_keys {
            break;
        }
    }
    debug!("payload = {}", payload.is_some());

    let payload = payload.ok_or_else(|| err_msg(ErrorKind::InvalidState, "Payload is none"))?;

    let payload = String::from_utf8(payload)
        .kind(ErrorKind::Malformed, "Authcrypt payload is invalid utf8")?;
    debug!("payload = {}", payload);

    let e = Envelope::from_str(&payload)?.parse()?.verify_didcomm()?;
    debug!("returning envelope type ({})", e.get_type());
    Ok(Some(e))
}
