# Affinidi Messaging - Mediator Service

[[_TOC_]]

## Overview

A DIDComm Messaging v2 mediator & relay service that listens to send &receive messages over https.

## Dependencies

To run the mediator, it requires these packages that is also part of the Affinidi Messaging project.

1. [affinidi-messaging-didcomm](../affinidi-messaging-didcomm/) - Affinidi Messaging DIDComm implementation, a modified version of [didcomm-rust](https://github.com/sicpa-dlab/didcomm-rust) project.
2. [affinidi-messaging-sdk](../affinidi-messaging-sdk/) - a Software Development Kit (SDK) to simplify the implementation of Affinidi Messaging into your application.

## Prerequisites

To build and run this project, you need to set up the following:

1. Install Rust on your machine if you haven't installed it yet using [this guide](https://www.rust-lang.org/tools/install).
2. Install the Docker on your machine if you haven't installed it yet using [this guide](https://docs.docker.com/desktop/). We will need this to run Redis instance for the mediator.

## Running affinidi-messaging-mediator service

1. Run Redis docker container using the command below:

   ```bash
   docker run --name=redis-local --publish=6379:6379 --hostname=redis --restart=on-failure --detach redis:latest
   ```

2. Navigate to the `affinidi-messaging-mediator` subfolder and create certificates for `affinidi-messaging-mediator` service:

   ```bash
   cd affinidi-messaging-mediator
   cargo run --example create_local_certs
   ```

   This will generate certificate files in the `affinidi-messaging-mediator/conf/keys` folder. You should use `client.chain` file to override the default SSL certificates in `affinidi-messaging-sdk`, like:

   ```rust
   let mut config = Config::builder()
       .with_ssl_certificates(&mut vec![
           "../affinidi-messaging-mediator/conf/keys/client.chain".into()
       ])
   ```

3. In the same `affinidi-messaging-mediator` subfolder run the following command to generate DID and the corresponding keys:

   ```bash
   cargo run --example generate_secrets
   ```

   This will generate `affinidi-messaging-mediator/conf/secrets.json-generated` file containing a did:peer together with the pair of keys for verification and encryption and `jwt_authorization_secret` you shall use for `jwt_authorization_secret` value in `mediator.toml`.
   Use the generated did:peer as a value for `<MEDIATOR_DID>` placeholder in following commands as well as in [affinidi-messaging-sdk - Examples](../affinidi-messaging-sdk#examples).

4. Save the generated `secrets.json-generated` file as `affinidi-messaging-mediator/conf/secrets.json`.

5. Start `affinidi-messaging-mediator` service via:

   ```bash
   cd affinidi-messaging-mediator
   export MEDIATOR_DID=did://<MEDIATOR_DID>
   export REDIS_URL=redis://@localhost:6379
   cargo run
   ```

## Examples

Refer to [affinidi-messaging-sdk - Examples](../affinidi-messaging-sdk#examples).
