//! Example Trust Ping using the Affinidi Trust Messaging SDK
//! Pings the mediator from Alice
//! Will use HTTPS and then WebSocket

use affinidi_messaging_didcomm::{error::ResultExtNoContext, secrets::Secret};
use affinidi_messaging_helpers::common::profiles::Profiles;
use affinidi_messaging_sdk::{
    config::Config, errors::ATMError, messages::GetMessagesRequest, protocols::Protocols, ATM,
};
use askar_crypto::alg::p256::P256KeyPair;
use askar_crypto::jwk::FromJwk;
use base64::prelude::*;
use clap::Parser;
use num_bigint::{BigInt, BigUint};
use p256::{ecdsa::VerifyingKey, elliptic_curve::PublicKey, NistP256};
use serde_json::Value;
use std::{
    env,
    time::{Duration, SystemTime},
};
use tracing::{error, info};
use tracing_subscriber::filter;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    profile: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), ATMError> {
    let args: Args = Args::parse();

    let (profile_name, profile) = Profiles::smart_load(args.profile, env::var("AM_PROFILE").ok())
        .map_err(|err| ATMError::ConfigError(err.to_string()))?;
    println!("Using Profile: {}", profile_name);

    // construct a subscriber that prints formatted traces to stdout
    let subscriber = tracing_subscriber::fmt()
        // Use a more compact, abbreviated log format
        .with_env_filter(filter::EnvFilter::from_default_env())
        .finish();
    // use that subscriber to process traces emitted after this point
    tracing::subscriber::set_global_default(subscriber).expect("Logging failed, exiting...");

    let alice = if let Some(alice) = profile.friends.get("Alice") {
        alice
    } else {
        return Err(ATMError::ConfigError(
            format!("Alice not found in Profile: {}", profile_name).to_string(),
        ));
    };

    let mut config = Config::builder()
        .with_my_did(&alice.did)
        .with_atm_did(&profile.mediator_did)
        .with_websocket_disabled()
        .with_non_ssl()
        .with_atm_api(&profile.network_address);

    if let Some(ssl_cert) = &profile.ssl_certificate {
        config = config.with_ssl_certificates(&mut vec![ssl_cert.to_string()]);
        println!("Using SSL Certificate: {}", ssl_cert);
    }

    // Create a new ATM Client
    let mut atm = ATM::new(config.build()?).await?;
    let protocols = Protocols::new();

    // Add our secrets to ATM Client - stays local.
    //    atm.add_secret(
    //        alice
    //            .get_key("#zDnaefQTBNTzvoy2dHMRMAWMbxfKGCjmCqLK921e8ARznRsmN")
    //            .unwrap(),
    //   );
    //atm.add_secret(alice.get_key("#key-2").unwrap());

    // Add the mediator secret
    atm.add_secret(serde_json::from_str(r#"
    {
        "id": "did:peer:2.Vz6Mkvw3cBJpxm7475pXPHDr7tMbRsDurUji715cx97A8V1vq.VzDnaeiF8YrdnpKuxgaWLmLaj5TfqyX2AVMnAhrS1sVmAmyMtt.EzQ3shQXXrEc3SBFeHhvemiZkeuePQ2KmJUro2otxNiz6E784q.EzDnaerZYqiX32LPjbKS8Ewn11AGwpmJHwhGduamisG3WWz3LM.SeyJ0IjoiRElEQ29tbU1lc3NhZ2luZyIsInMiOnsidXJpIjoiaHR0cDovLzEzLjIxMi4xNDguMTgwOjcwMzcvbWVkaWF0b3IvdjEiLCJhIjpbImRpZGNvbW0vdjIiXSwiciI6W119LCJpZCI6bnVsbH0#key-1",
        "type": "JsonWebKey2020",
        "privateKeyJwk": {
            "crv": "Ed25519",
            "d": "qvLTDd4nDR3Yy5f4Y1MGpFeXdxzB8ZraohY5ugYSQHM",
            "kty": "OKP",
            "x": "9Nkwio0ZNOGSamKT5zQTPTzRu4ETV1ctWgRAoy37FSI"
        }
    }
    "#).unwrap());
    atm.add_secret(serde_json::from_str(r#"
    {
        "id": "did:peer:2.Vz6Mkvw3cBJpxm7475pXPHDr7tMbRsDurUji715cx97A8V1vq.VzDnaeiF8YrdnpKuxgaWLmLaj5TfqyX2AVMnAhrS1sVmAmyMtt.EzQ3shQXXrEc3SBFeHhvemiZkeuePQ2KmJUro2otxNiz6E784q.EzDnaerZYqiX32LPjbKS8Ewn11AGwpmJHwhGduamisG3WWz3LM.SeyJ0IjoiRElEQ29tbU1lc3NhZ2luZyIsInMiOnsidXJpIjoiaHR0cDovLzEzLjIxMi4xNDguMTgwOjcwMzcvbWVkaWF0b3IvdjEiLCJhIjpbImRpZGNvbW0vdjIiXSwiciI6W119LCJpZCI6bnVsbH0#key-2",
        "type": "JsonWebKey2020",
        "privateKeyJwk": {
            "crv": "P-256",
            "d": "aMdJC_1c2i3mLkWXJz0WJArXMXB70L1CUtIFRH-jzto",
            "kty": "EC",
            "x": "CKu4ykvQzNJyHwmjPVBrSQ2Hhi7lDWDAhx84ss2HI7E",
            "y": "Wg2PsYOtpKMDQTULs9sc-nGbW6-6GEInCp3ejQwZHoU"
        }
    }
    "#).unwrap());
    atm.add_secret(serde_json::from_str(r#"
    {
        "id": "did:peer:2.Vz6Mkvw3cBJpxm7475pXPHDr7tMbRsDurUji715cx97A8V1vq.VzDnaeiF8YrdnpKuxgaWLmLaj5TfqyX2AVMnAhrS1sVmAmyMtt.EzQ3shQXXrEc3SBFeHhvemiZkeuePQ2KmJUro2otxNiz6E784q.EzDnaerZYqiX32LPjbKS8Ewn11AGwpmJHwhGduamisG3WWz3LM.SeyJ0IjoiRElEQ29tbU1lc3NhZ2luZyIsInMiOnsidXJpIjoiaHR0cDovLzEzLjIxMi4xNDguMTgwOjcwMzcvbWVkaWF0b3IvdjEiLCJhIjpbImRpZGNvbW0vdjIiXSwiciI6W119LCJpZCI6bnVsbH0#key-3",
        "type": "JsonWebKey2020",
        "privateKeyJwk": {
            "crv": "secp256k1",
            "d": "Cs5xn7WCkUWEua5vGxjP9_wBzIzMtEwjQ4KWKHHQR14",
            "kty": "EC",
            "x": "Lk1FY8MmyLjBswU4KbLoBQ_1THZJBMx2n6aIBXt1uXo",
            "y": "tEv7EQHj4g4njOfrsjjDJBPKOI9RGWWMS8NYClo2cqo"
        }
    }
    "#).unwrap());
    atm.add_secret(serde_json::from_str(r#"
    {
        "id": "did:peer:2.Vz6Mkvw3cBJpxm7475pXPHDr7tMbRsDurUji715cx97A8V1vq.VzDnaeiF8YrdnpKuxgaWLmLaj5TfqyX2AVMnAhrS1sVmAmyMtt.EzQ3shQXXrEc3SBFeHhvemiZkeuePQ2KmJUro2otxNiz6E784q.EzDnaerZYqiX32LPjbKS8Ewn11AGwpmJHwhGduamisG3WWz3LM.SeyJ0IjoiRElEQ29tbU1lc3NhZ2luZyIsInMiOnsidXJpIjoiaHR0cDovLzEzLjIxMi4xNDguMTgwOjcwMzcvbWVkaWF0b3IvdjEiLCJhIjpbImRpZGNvbW0vdjIiXSwiciI6W119LCJpZCI6bnVsbH0#key-4",
        "type": "JsonWebKey2020",
        "privateKeyJwk": {
            "crv": "P-256",
            "d": "LZaQSJnl6_7-VtcZahCbiHpRQDNhWA7KRs6g20u_Wl4",
            "kty": "EC",
            "x": "hEEjK3_80e7DDzibXAX66-uKM8mZuq7EB6LLiAuJnYI",
            "y": "PaWjK4KtMK6KUSFp2_ACYPPlikLBmKXhfPSZvFN6xus"
        }
    }
    "#).unwrap());

    // Ready to send a trust-ping to ATM
    let start = SystemTime::now();

    // You normally don't need to call authenticate() as it is called automatically
    // We do this here so we can time the auth cycle
    //atm.authenticate().await?;

    let glenn = r#"
    {
    "ciphertext": "7hDJkgXz4E1eFoaaRzOzcH_tWaWmGGHt0Z6Ya3NgJXPUT7HiffFg4uLbGpk-NQ4lJKn1sVIbP7Qb89RrS10aYwcCQkyrIOe2HZDTaWaZYIpayPliAeBVa9EmkBmBW6rZHF162uum-wC-8AAV_2--cpHCBYFcNA-wDb9Jc3_9OpFw_q6QYGN5h-oA7bMRgLod_2NwHTziE9lzEQOjKkUP4SnFBTLo4V2hQS70727D8jUGaPNyGHYnkjyC86EtHoPP01I_D0Z2Bs4d6xAH0bSPoU70vq4XKDypUObJ7kbasAqmLPftGNcN3UDUOJJdGY0Pmcos0b4hEGV4weELMC6cTBnoDp7LIrV4C30o9rHBj5ctrIdJ4ugcs6Nm5xqCrirV-Y1V27ydFhIc3TaBO9e7T0dxWkB6KunQwipXlyC64xMrhogJ0B2U0kq-LjKolr2eQ4puNV8fejrWpaeTbJcfL9o8h3P9vVRsjsH-ZATxxlsPD5F37MSM_WkqSVeoVzfWQH887OGeiMxxWysjxrhNo_rxRE2flpMAH6WBVYw6cy51O_C_RVJPJqTebXJN_xDqmzQNooiHu06pQ_EzCzK_AlviJ3S7ns5xmXiZhzwCvU_aLyiLg4WWbSs76Q1fCl3Yj2CwcecWo8Cd7Z1s3GoZWqLgr7IzyyIxQ4zDBNqPvsF2S5zqiz89kJIJQZQo0MO1qeHGdbxjda202mDja_K5hoI8g4wUUfivHjUk8lAkf2iarz341rnaneMSdB3FyCfnCVCWsFJXsXYU9eO9tbRZ00jS7WgpYHj4PLZeJXR4cZWCJOMqHRBb3LBO_TW3za_Y3oDnsv7nwypUCOAYtBP3R_vK4tF-chN9gZf63veka0ER5weQm4LR-pz0Zfo61r5cqpXIC8AnVdJ0uz89aqzPhXKFO_DznZqZdMsuiudgVjh5ZvW_lpQBgYPtMmEryy8Nvbb1d5IvfOJ3MaSciRGCm0jk3fl6aiUXG2U_ia042fo",
    "protected": "eyJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYWxnIjoiRUNESC0xUFUrQTI1NktXIiwiYXB1IjoiWkdsa09tdGxlVHA2Ukc1aFpXUlJVWEJ5Y3pKdFkxcHpSVE16Y1hKalpXOW1PV1pNUkVOemVFVlRXSGRLUTBobVdqbGFaVXRHWm5GWkkzcEVibUZsWkZGUmNISnpNbTFqV25ORk16TnhjbU5sYjJZNVpreEVRM040UlZOWWQwcERTR1phT1ZwbFMwWm1jVmsiLCJza2lkIjoiZGlkOmtleTp6RG5hZWRRUXByczJtY1pzRTMzcXJjZW9mOWZMRENzeEVTWHdKQ0hmWjlaZUtGZnFZI3pEbmFlZFFRcHJzMm1jWnNFMzNxcmNlb2Y5ZkxEQ3N4RVNYd0pDSGZaOVplS0ZmcVkiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIiwiYXB2IjoiN0dzYl9jbjJHNGNNM21TSmJkZzB3NmVfV0QzUVVEM2J3T2hrejloeG5qNCIsImVwayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IlJNN1BlNTN4YWFLRjMyWFdWb2lnek1NTmdNVWtWdXVPQ2c4dmw0dmRkaEkiLCJ5IjoiRzV1SndkRHhLNlUwX0dTQ0dFZ0RDZzJTU0NFT2tNZHJUS3NsRkZpRXBRIn19",
    "tag": "K7RuCQyTOwfbNzAH83sSnBdVYJ5E1nOlQPn1WXCmges",
    "iv": "06a3tdxJs4wh48uN2ThC5w",
    "recipients": [
        {
            "header": {
                "kid": "did:peer:2.Vz6Mkvw3cBJpxm7475pXPHDr7tMbRsDurUji715cx97A8V1vq.VzDnaeiF8YrdnpKuxgaWLmLaj5TfqyX2AVMnAhrS1sVmAmyMtt.EzQ3shQXXrEc3SBFeHhvemiZkeuePQ2KmJUro2otxNiz6E784q.EzDnaerZYqiX32LPjbKS8Ewn11AGwpmJHwhGduamisG3WWz3LM.SeyJ0IjoiRElEQ29tbU1lc3NhZ2luZyIsInMiOnsidXJpIjoiaHR0cDovLzQ3LjEyOS4xMDguMjIzOjcwMzcvIiwiYSI6WyJkaWRjb21tL3YyIl0sInIiOltdfSwiaWQiOm51bGx9#key-4"
            },
            "encrypted_key": "8W10kk4Dh7tIdrP0-Vk1fag9AbFAVUETUlTEXTrXFm_CRfAWeAqIBDzTxVw1KQ_QQYqqq3fJq7BxkrKbwHTz_PWW9QCgI1lQ"
        }
    ]
}
    "#;

    let adam = r#"
    {"ciphertext":"82yQaMI-Upd44xhO3BcHqzdNU4vyjmR-mXBjyeW59060ve2um2KsMaaWDIGjrKMJ0z-DK6qhL2st-_7-ZFgasPXKO-zZVjKMD9l1ZSfEEgTxbWbbJpUQ-oJiBMg03EvOEKhyJZvbIbdNF5N6dITjn-UB7jkGR8P-nVBO5ccHifz4eG1aNIlstuwGgKCQk_4I6xQRF-U2SQw_fl-6pdCXOVg5O4WUsABK2wWcwzSLyJYfLtK9mb6GU1LtDLFDkZwZYu0DThnxDGaCBI4URZnnxfMViLsvacfvcMQQnKvDFgobRS4kedWMXnrPeUnaGVm5DhjdrAeek0sZ_ViVthoFCglsQD0mXKjOBP91qCcQqQ866dhGt5eU3flojVKjub4_jxuqexChIJu-O9NAvt2XNDRIBtCbBld5SAjGjZnzHmG6AtRM1h0v5-MVLuDiTcyteK1NAak3fK3d2ZZP0kvOVNOwcOtJRSu_WNj1CGM_1LYAmjulzSqX13ZsiLWPNu4XLBn8uYriBjmWirDtHHf6SC8MTpUN7LRNyq9FgYMq5taqZf4vNUmLlgbhxJsgf-SiHxTDv1jzB0F286X-gwArPc1Gq2ONS2tLpE0GaSCMSpjXhuncGGixnM_t6XqTbmpa0tT2kKbsGiTrH4yDT3HrMMe85jYfuVLR7Hia_fChaix-6kQRcipCeT5OW1PNgcZ1a1YCUeT-LMdB9H2dnax4MZQer3InWzCgILNEYZvcRYy4FWXwPgIp0P575n0MNXtsCGp8pS6GEwFAZYuS0P7vdzS26vQb4fdZQnmOJQPrL4L7Pa38R4ls1CRr-u5TpdDSOV00-FJJg1nxEkNXHQx5CaNswvGVUWUa_qJ9hKs2RDcFleiqiPt9a9-zsf_yUev5H-7mNtA_e9ZT500f88p1li3uIzfLw7JocuyK9izTpoGSc7LUKUZQH2GiL6iVH1LOTzhuB3ztFG484H5f5FwqRA","protected":"eyJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYWxnIjoiRUNESC0xUFUrQTI1NktXIiwiYXB1IjoiWkdsa09tdGxlVHA2Ukc1aFpXWlJWRUpPVkhwMmIza3laRWhOVWsxQlYwMWllR1pMUjBOcWJVTnhURXM1TWpGbE9FRlNlbTVTYzIxT0kzcEVibUZsWmxGVVFrNVVlblp2ZVRKa1NFMVNUVUZYVFdKNFprdEhRMnB0UTNGTVN6a3lNV1U0UVZKNmJsSnpiVTQiLCJza2lkIjoiZGlkOmtleTp6RG5hZWZRVEJOVHp2b3kyZEhNUk1BV01ieGZLR0NqbUNxTEs5MjFlOEFSem5Sc21OI3pEbmFlZlFUQk5UenZveTJkSE1STUFXTWJ4ZktHQ2ptQ3FMSzkyMWU4QVJ6blJzbU4iLCJhcHYiOiJFUjBsa0h5bzJRWW5SVDdJSEdOME9IOHd2Mmh2ZDhjdzkxWGtIajQxOWlJIiwiZXBrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiWUtrMWtxNHdITDRsMjlsNzNxUF9ZdFVBUktKZGFsMHNXdTY3SzdYTWRtUSIsInkiOiJBTm84UEo1cEFTSXd5QUwwNFhJWlg1Vnl1RjQ0aVNfU19DMGxDVjJVOWNFUSJ9fQ","tag":"d3pf1o7zMsOhThZLw70cKrNaZXxyudCRRUPzIkL9VX0","iv":"CE6asTjdiUKq8hvG7A7hmg","recipients":[{"header":{"kid":"did:peer:2.Vz6Mkvw3cBJpxm7475pXPHDr7tMbRsDurUji715cx97A8V1vq.VzDnaeiF8YrdnpKuxgaWLmLaj5TfqyX2AVMnAhrS1sVmAmyMtt.EzQ3shQXXrEc3SBFeHhvemiZkeuePQ2KmJUro2otxNiz6E784q.EzDnaerZYqiX32LPjbKS8Ewn11AGwpmJHwhGduamisG3WWz3LM.SeyJ0IjoiRElEQ29tbU1lc3NhZ2luZyIsInMiOnsidXJpIjoiaHR0cDovLzEzLjIxMi4xNDguMTgwOjcwMzcvbWVkaWF0b3IvdjEiLCJhIjpbImRpZGNvbW0vdjIiXSwiciI6W119LCJpZCI6bnVsbH0#key-4"},"encrypted_key":"8GjgvoreO43MceWJ9FGuf3PkTnDbWbnPMY0pcC2NURIvKXUlWVr9l90rBe5yG47v5w84xDj1CPqbKOmJxHxwsXGaVwAAp1Ka"}]}
    "#;

    //atm.unpack(adam).await?;

    /* Working example */
    /*
    let epk = r#"
    {"crv": "P-256",
    "kty": "EC",
    "x": "WAjiY05BRTlv7wGX_4RE6YX680GuuTS75yYk-F76BDw",
    "y": "RtXty6T9zREPIyNYI3LrqE0bv-woiKOq1OVkeoHwAEU"
    }
    "#;
    */

    /* Failing set */

    let epk = r#"
    {
        "kty": "EC",
        "crv": "P-256",
        "x": "RM7Pe53xaaKF32XWVoigzMMNgMUkVuuOCg8vl4vddhI",
        "y": "G5uJwdDxK6U0_GSCGEgDCg2SSCEOkMdrTKslFFiEpQ"
    }
    "#; //m

    let epk_v: Value = serde_json::from_str((epk)).unwrap();

    let x = BASE64_URL_SAFE_NO_PAD
        .decode(epk_v.get("x").unwrap().as_str().unwrap())
        .unwrap();
    let y = BASE64_URL_SAFE_NO_PAD
        .decode(epk_v.get("y").unwrap().as_str().unwrap())
        .unwrap();

    print!("x(raw): ");
    for c in &x {
        print!("{:02x}", c);
    }
    println!();
    print!("y(raw): ");
    for c in &y {
        print!("{:02x}", c);
    }
    println!();

    let x_be = BigUint::from_bytes_be(&x);
    let y_be = BigUint::from_bytes_be(&y);
    println!("x_be: {}", x_be);
    println!("y_be: {}", y_be);

    match P256KeyPair::from_jwk(epk) {
        Ok(key) => {
            println!("Key: {:?}", key);
        }
        Err(err) => println!("Error: {:?}", err),
    }

    match PublicKey::<NistP256>::from_jwk_str(epk) {
        Ok(key) => {
            println!("Key: {:?}", key);
        }
        Err(err) => println!("Error: {:?}", err),
    }

    Ok(())
}
