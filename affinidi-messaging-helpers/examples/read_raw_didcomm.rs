/*!
 * This is a test app that can read raw DIDComm messages to help in troubleshooting what is happening.
 *
 * To read the DIDComm messages, you will need access to the Secrets for the DID Recipients
 */

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_messaging_didcomm::{AttachmentData, envelope::MetaEnvelope};
use affinidi_messaging_sdk::{ATM, config::ATMConfig, errors::ATMError, profiles::ATMProfile};
use affinidi_tdk::{
    common::TDKSharedState,
    secrets_resolver::{SecretsResolver, secrets::Secret},
};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use clap::Parser;
use console::style;
use std::{
    fs::File,
    io::{self, BufRead, Read},
};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Raw DIDComm message
    #[arg(short, long)]
    raw_message: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), ATMError> {
    // Create a new ATM Client
    let config = ATMConfig::builder();
    let tdk = TDKSharedState::default().await;
    let atm = ATM::new(config.build()?, tdk).await?;

    // Local DID Resolver
    let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .map_err(|e| {
            ATMError::DIDError(format!("Couldn't instantiate DID Resolver. Reason: {}", e))
        })?;

    // Load the DIDComm message
    println!("{}", style("Raw DIDComm Message troubleshooting").green(),);

    // let args: Args = Args::parse();
    // let raw_message = match args.raw_message {
    //     Some(raw_message) => raw_message,
    //     None => {
    //         println!("{}", style("No DIDComm message provided").red());
    //         return Ok(());
    //     }
    // };

    for x in 0..30 {
        println!("Number of Message!!!!!!!!!");
        println!("{}", x);
    // }

    // let x = 0;
    // let x = "-signed";

        let raw_message = "message".to_string() + &x.to_string() + ".txt";

        let mut file = File::open(&raw_message).map_err(|e| {
            ATMError::ConfigError(format!("Can't open file ({}). Reason: {}", raw_message, e))
        })?;
        let mut didcomm_raw_message = String::new();
        file.read_to_string(&mut didcomm_raw_message).map_err(|e| {
            ATMError::ConfigError(format!(
                "Couldn't read file ({}) contents. Reason: {}",
                raw_message, e
            ))
        })?;

        println!();
        println!(
            "{}",
            style("Reading the DIDComm message envelope...").blue()
        );

        let envelope = MetaEnvelope::new(&didcomm_raw_message, &did_resolver)
            .await
            .map_err(|e| {
                ATMError::DidcommError(
                    "NA".to_string(),
                    format!("Couldn't read DIDComm raw message: {}", e),
                )
            })?;

        println!(
            "{}",
            style(format!("\tFrom DID: {:?}", envelope.from_did)).cyan()
        );
        println!(
            "{}",
            style(format!("\t  To DID: {:?}", envelope.to_did)).cyan()
        );
        println!(
            "{}",
            style(format!("\tMSG Hash: {}", envelope.sha256_hash)).cyan()
        );

        let Some(to_did) = envelope.to_did else {
            println!(
                "{}",
                style("Couldn't find the recipient DID. Exiting...").red()
            );
            return Ok(());
        };

        // Grab the secrets
        let stdin = io::stdin();
        let _lines = stdin.lock().lines();
        let mut raw_secrets = String::new();

        raw_secrets.push_str("[{\"id\": \"did:key:zQ3shTL7MW8nKRhACRkTmc4EHdmEnZyaJFH3zcksoeY2sYAtq#zQ3shTL7MW8nKRhACRkTmc4EHdmEnZyaJFH3zcksoeY2sYAtq\",\"type\": \"JsonWebKey2020\",\"privateKeyJwk\": {\"kid\": \"did:key:zQ3shTL7MW8nKRhACRkTmc4EHdmEnZyaJFH3zcksoeY2sYAtq#zQ3shTL7MW8nKRhACRkTmc4EHdmEnZyaJFH3zcksoeY2sYAtq\",\"kty\": \"EC\",\"crv\": \"secp256k1\",\"x\": \"V_M-9D36VFBs1u-4dbJWZYofloQ8H9u6ZeJGmrJgq9o\",\"y\": \"e0wmnK0dr26-GhzP8WwDLPywAOqM40e24NLwRh6N33Q\",\"d\": \"IWu9tivhmh1GgW-5fbLCXvFPeN3xxCqV7gjE76qN7VM\"}}]");
        // raw_secrets.push_str("[{\"id\": \"did:key:zDnaepZeT7HDHa6SLYw4Xomd25yN2V95qaKXiGUtpFLvs8uAV#zDnaepZeT7HDHa6SLYw4Xomd25yN2V95qaKXiGUtpFLvs8uAV\",\"type\": \"JsonWebKey2020\",\"privateKeyJwk\": {\"kid\": \"did:key:zDnaepZeT7HDHa6SLYw4Xomd25yN2V95qaKXiGUtpFLvs8uAV#zDnaepZeT7HDHa6SLYw4Xomd25yN2V95qaKXiGUtpFLvs8uAV\",\"kty\": \"EC\",\"crv\": \"P-256\",\"x\": \"ZpAbZaLOpln4wYAcozZvRkD03zSnUmsbHcPcmMQ4Zo4\",\"y\": \"C7dbfuHCme0-ka_HxzbAhJYLCNxJjFEVhDIz4vWl6xk\",\"d\": \"yMFWj09rkpkPh-uXfYqipDJlhTJw06_u3s_u93E3cKw\"}}]");


        let secrets: Vec<Secret> = match serde_json::from_str(&raw_secrets) {
            Ok(secrets) => secrets,
            Err(e) => {
                println!(
                    "{}",
                    style(format!("Error converting secrets: {}", e)).red()
                );
                return Ok(());
            }
        };
        atm.get_tdk().secrets_resolver.insert_vec(&secrets).await;

        let profile = ATMProfile::new(&atm, None, to_did.clone(), None).await?;
        atm.profile_add(&profile, false).await?;
        println!("{}", style("DIDComm Profile created...").green());

        let (inner_message, meta) = atm.unpack(&didcomm_raw_message).await?;

        println!("{}", style("DIDComm Message").green());
        println!();

        println!("{}", style(format!("{:#?}", meta)).yellow());
        println!();
        println!("{}", style(format!("{:#?}", inner_message)).green());

        // >>>>> Additional processing of the message can be done here <<<<<

        if inner_message.type_ == "https://didcomm.org/routing/2.0/forward" {
            println!();
            println!("{}", style("Forwarded Message").green());
            if let Some(attachments) = inner_message.attachments {
                let attachment = attachments.first().unwrap();
                let data = match attachment.data {
                    AttachmentData::Base64 { ref value } => {
                        String::from_utf8(BASE64_URL_SAFE_NO_PAD.decode(&value.base64).unwrap())
                            .unwrap()
                    }
                    AttachmentData::Json { ref value } => {
                        if value.jws.is_some() {
                            println!("{}", style("JWS is not supported").red());
                            return Ok(());
                        } else {
                            match serde_json::to_string(&value.json) {
                                Ok(data) => data,
                                Err(e) => {
                                    println!(
                                        "{}",
                                        style(format!("Error converting JSON: {}", e)).red()
                                    );
                                    return Ok(());
                                }
                            }
                        }
                    }
                    _ => {
                        println!("{}", style("Unsupported attachment type").red());
                        return Ok(());
                    }
                };
                println!("{}", style("Forwarded message found").green());
                println!();
                println!("{}", style(data).green());
            }
        }

    }
    Ok(())
}
