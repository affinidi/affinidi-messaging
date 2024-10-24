# Affinidi Trust Network - Affinidi Trusted Messaging

## Changelog history

## 22nd September 2024 (0.8.0)

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

### Affinidi Processors

* Created forwarding processor
  * Can run as a task within the mediator
  * Optionally, can run as a separate process independently of the mediator

### Affinidi Messaging SDK

* Added forwarding/routing support
* Added routing example
* Added add_secrets() method to add more than one secret at a time
