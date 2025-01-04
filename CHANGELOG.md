# Affinidi Trust Network - Affinidi Trusted Messaging

## Changelog history

## xxx January 2025 (0.8.8)

### All (0.8.8)

* Added Global-ACL Support

### Mediator (0.8.8)

* Added Global ACL Support
* Added default_acl to `security` block in configuration
  * Allows to set the default ACL to apply
  * Default ACL for both global and local ACL
* New error type ACLDenied added
* Local Direct Delivery added
  * Allows for known recipient DIDs to receive messages directly sent to the
  mediator without wrapping them in a forward envelope

### SDK (0.8.8)

* Authentication will now fail due to ACL Errors and not retry.

### Affinidi Text Client (0.8.8)

* Updated ratatui-image from 3.x to 4.x

### Affinidi DIDComm (0.8.8)

* MetaEnvelope::new() no longer checks for recipient keys.
  * This has been shifted to the unpack() function
  * This allows for easier handling of any DIDComm message even if recipient is not known by it's secrets

## 16th December 2024 (0.8.1)

### All (0.8.1)

* Updating of required crates.
* Added affinidi-text-client to README

### Affinidi Text Client

* Fixed bug where the OOB invitation process would fail due to incorrect forward_and_send next address
* Fixed bug when displaying chat details, but the chat has been deleted
* Fixed bug when selecting next/previous chat when there are no chats

## 16th December 2024 (0.8.0)

### All

* Crates updated to latest versions
* Shifted crate dependency into top-level Cargo.toml

### Affinidi Mediator

* ACL support added
* DIDComm routing protocol (forwarding) implemented
* Mediator ADMIN accounts added
  * Allows for managing ACL's
* Mediator configuration modified to break config into clearer blocks
  * Breaking change. i.e. config items have changed names and blocks
* send_error_response() method added so that DIDComm error messages can be generated
  * Helps with sending error responses to WebSocket requests
* send_empty_ack_response() method added so that you can ack messages that have no response
* Ability to run the `forwarding` processor locally or remotely
* Redis updated from 0.26 to 0.27 and deadpool-redis from 0.17 to 0.18
* JWT Expiry configuration added
  * access tokens
  * refresh tokens
* Authentication refresh added
  * /authentication/refresh
* OOB Discovery Protocol Added
  * /oob
* Redis Database changes
  * Version check added
  * Redis 7.4 minimum version required
  * LUA scripts shifted
* FIX: deleting a message was returning the incorrect error response when the message_id didn't exist

### Affinidi Processors

* Created forwarding processor
  * Can run as a task within the mediator
  * Optionally, can run as a separate process independently of the mediator

### Affinidi Messaging SDK

* Added forwarding/routing support
* Added routing example
* Added add_secrets() method to add more than one secret at a time
* Added ability to support multiple DID Profiles per SDK ATM Instance
  * Ensures that each DID is authenticated separately, and has their own WebSocket connection
  * Can turn on live-delivery on a per DID basis, or all together
* Added different WebSocket operating modes
  1. Cached Mode: SDK Caches inbound messages and handles a lot of the heavy lifting for you
  2. DirectMode: No caching, you can request a broadcast channel and receive messages directly and handle the logic on the client side.
