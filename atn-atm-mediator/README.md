# didcomm-mediator

A DIDComm v2 mediator/relay service that listens to send/receive messages over https

A work in progress, may not work at all depending on what hacking Glenn is up to... :)

## Prerequisites

To build this project, you will also need to place the Rust did-peer implementation in a directory above (../did-peer).

The did-peer implementation can be found at [here](https://gitlab.com/affinidi/octo/Glenn/did-peer)

### Create SSL Keys for development/testing

Create server, intermediate, client and Root Certificate Authority keys and certs

`cargo run --example create_local_certs`

This will place the files under ***conf/keys***

Server will use the following files

* end.cert (SSL Certificate)
* end.key (SSL Certificate key)

Client will use the following file

* client.chain (Certificate Authority signing cert)

### Create the JWT secret

BASE64_URL_NOPAD encoded byte array.

Can be created with code similar to

```rust
    let doc = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    println!("{}", BASE64_URL_SAFE_NO_PAD.encode(doc.as_ref()));
```

## Crate Structure

didcomm-mediator is the overall Crate. It currently has the following sub-crates embedded in it (likely to be pulled out in the future)

1. didcomm-rust - a heavily modified implementation of a 3rd party didcomm library
2. atm-sdk - the SDK for Affinidi Trusted Messaging

## Examples

It is likely that the examples you are really looking for are situated in the atm_sdk crate!
