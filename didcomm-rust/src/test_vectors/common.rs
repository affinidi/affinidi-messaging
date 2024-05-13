use base64::prelude::*;
use serde_json::{Map, Value};

pub const ALICE_DID: &str = "did:example:alice";
pub const BOB_DID: &str = "did:example:bob";
pub const CHARLIE_DID: &str = "did:example:charlie";

pub fn update_field(msg: &str, field: &str, value: &str) -> String {
    let parsed: Value = serde_json::from_str(msg).unwrap();
    let mut msg_dict: Map<String, Value> = parsed.as_object().unwrap().clone();
    msg_dict.insert(String::from(field), value.into());
    serde_json::to_string(&msg_dict).unwrap()
}

pub fn remove_field(msg: &str, field: &str) -> String {
    let parsed: Value = serde_json::from_str(msg).unwrap();
    let mut msg_dict: Map<String, Value> = parsed.as_object().unwrap().clone();
    msg_dict.remove(field);
    serde_json::to_string(&msg_dict).unwrap()
}

pub fn update_protected_field(msg: &str, field: &str, value: &str) -> String {
    let parsed: Value = serde_json::from_str(msg).unwrap();
    let mut msg_dict: Map<String, Value> = parsed.as_object().unwrap().clone();

    let mut buffer = Vec::<u8>::new();
    BASE64_URL_SAFE_NO_PAD
        .decode_vec(
            msg_dict.get("protected").unwrap().as_str().unwrap(),
            &mut buffer,
        )
        .unwrap();
    let parsed_protected: Value = serde_json::from_slice(&buffer).unwrap();
    let mut protected_dict: Map<String, Value> = parsed_protected.as_object().unwrap().clone();
    protected_dict.insert(String::from(field), value.into());
    let protected_str = serde_json::to_string(&protected_dict).unwrap();
    println!("{}", &protected_str);
    let protected_str_base64 = BASE64_URL_SAFE_NO_PAD.encode(protected_str);
    msg_dict.insert(String::from("protected"), protected_str_base64.into());
    serde_json::to_string(&msg_dict).unwrap()
}

pub fn remove_protected_field(msg: &str, field: &str) -> String {
    let parsed: Value = serde_json::from_str(msg).unwrap();
    let mut msg_dict: Map<String, Value> = parsed.as_object().unwrap().clone();

    let mut buffer = Vec::<u8>::new();
    BASE64_URL_SAFE_NO_PAD
        .decode_vec(
            msg_dict.get("protected").unwrap().as_str().unwrap(),
            &mut buffer,
        )
        .unwrap();
    let parsed_protected: Value = serde_json::from_slice(&buffer).unwrap();
    let mut protected_dict: Map<String, Value> = parsed_protected.as_object().unwrap().clone();
    protected_dict.remove(field);
    let protected_str = serde_json::to_string(&protected_dict).unwrap();
    let protected_str_base64 = BASE64_URL_SAFE_NO_PAD.encode(protected_str);

    msg_dict.insert(String::from("protected"), protected_str_base64.into());
    serde_json::to_string(&msg_dict).unwrap()
}
