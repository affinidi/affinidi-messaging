use std::io;

use axum::{
    extract::{Path, State},
    Json,
};
use didcomm::{did::DIDResolver, Message, UnpackOptions};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    common::errors::{AppError, GenericDataStruct, Session, SuccessResponse},
    resolvers::{affinidi_dids::AffinidiDIDResolver, affinidi_secrets::AffinidiSecrets},
    SharedData,
};

#[derive(Serialize, Deserialize, Debug)]
pub struct RecipientHeader {
    pub kid: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Recipient {
    pub header: RecipientHeader,
    pub encrypted_key: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct InboundMessage {
    pub protected: String,
    pub recipients: Vec<Recipient>,
    pub iv: String,
    pub ciphertext: String,
    pub tag: String,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct ResponseData {
    pub name: String,
}
impl GenericDataStruct for ResponseData {}

pub async fn message_inbound_handler(
    session: Session,
    State(state): State<SharedData>,
    Json(body): Json<InboundMessage>,
) -> Result<(StatusCode, Json<SuccessResponse<ResponseData>>), AppError> {
    let s = serde_json::to_string(&body).unwrap();
    println!("{}", s);
    match Message::unpack(
        &s,
        &state.did_resolver,
        &state.config.mediator_secrets,
        &UnpackOptions::default(),
    )
    .await
    {
        Ok((metadata, msg)) => {
            println!("Unpacked metadata is\n{:#?}\n", metadata);
            println!("Unpacked message is\n{:#?}\n", msg);
        }
        Err(e) => println!("ERROR: {:?}", e),
    }

    let response_data = ResponseData {
        name: "Woot".into(),
    };

    Ok((
        StatusCode::OK,
        Json(SuccessResponse {
            transactionID: session.tx_id,
            httpCode: StatusCode::OK.as_u16(),
            errorCode: 0,
            errorCodeStr: "NA".to_string(),
            message: "Success".to_string(),
            data: response_data,
        }),
    ))
}
