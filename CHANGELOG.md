# Affinidi Trust Network - Affinidi Trusted Messaging

## Changelog history

## XX January 2025 (0.9.4)

### DIDComm Library

* Cleaned up unneeded lifetime parameters
* Changed how DID Document Verification Methods are discovered, more robust algorithm used
* Tested multi-key recipient sending/receiving - some changes required to pack/unpack

### Mediator (0.9.4)

* Removing Accounts implemented with full cleanup of associated data
* Database Schema version is now recorded, allows for upgrade paths when schema changes
* Mediator Account Type added, allows for treating the Mediator DID separately
* FIX: Trying to strip admin rights from an empty list will now correctly create a ProblemReport that explains the issue
* FIX: Mediator Administration generates a client side error when no Admin DID is selected when removing Admin Accounts

### SDK (0.9.4)

* FIX: If ProblemReport had no args, deserializing would fail as no args field. Now defaults to empty array correctly
* TEST: Added ProblemReport tests to check for empty args and serialization/deserialization

## 18th January 2025 (0.9.2)

### Mediator (0.9.2)

* WebSocket connections will now close when the auth session token expires.
* Logging can be configured to use JSON or not (log_json)
* JWT_EXPIRY_TOKEN has a minimum of 10 seconds enforced to stop an issue where clients can get stuck in an
endless refresh loop

### SDK (0.9.2)

* authentication logic will trigger a token refresh if <5 seconds remain on the expiry token (was 10 seconds)
* Fix: refresh retry logic where there was a lock related bug on authentication refresh tokens

## 17th January 2025 (0.8.10)

* Fix Axum Path routes for new version. Internal only.

## 16th January 2025 (0.8.9)

### All (0.8.9)

* Added Global-ACL Support

### Mediator (0.8.9)

* Added Global ACL Support
* Added default_acl to `security` block in configuration
  * Allows to set the default ACL to apply
* New error type ACLDenied added
* Local Direct Delivery added
  * Allows for known recipient DIDs to receive messages directly sent to the
  mediator without wrapping them in a forward envelope

### SDK (0.8.9)

* Authentication will now fail due to ACL Errors and not retry.
* Deleting Messages has been split between direct and background
  * Direct: immediate deletion and the main thread will block
  * Background: requests are handled via a background task

### Affinidi Text Client (0.8.9)

* Updated ratatui-image from 3.x to 4.x

### Affinidi DIDComm (0.8.9)

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
