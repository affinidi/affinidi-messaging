# Affinidi Trust Network - Affinidi Trusted Messaging - Mediator Service

## Changelog history

## 20th July 2024

* Message Pickup Message-Delivery and Messages Received implemented

## 24th June 2024

* Added streaming.enabled configuration option

### 21st June 2024

* Refactored process() on inbound messages so that there is an option to store the message response - some responses are live only, if no connection then no need to do anything more.
* Added delta difference on statistics reporting

### 20th June 2024

* Updating mediator statistics and metrics to improve clarity
  * Added websocket connections
  * DELETED_BYTES
  * SENT_BYTES
* Improved websocket handling of closed connections with error handling
* Added authenticated session metrics (created and success)

### 15th June 2024

* Statistics reporting thread implemented

### 13th June 2024

* WebSocket implementation handler implemented. More work to be done.

### 12th June 2024

* Removed unused configuration options (allow/deny lists)
* Added method to load Mediator secrets from AWS Secrets Manager
* Added method to load the mediator DID from AWS Systems Manager Parameter Store
* Added method to load the jwt secret key from AWS Secrets Manager

### 9th June 2024

* Refactored inbound message handling so it returns more relevant information to clients

### 8th June 2024

* Refactored namespace for several SDK structs
* implementing ability to get messages via REST API

### 7th June 2024

* Added authentication check on database session.state, protects against replay attack.
* Added Sha256 hash of DID to Session Struct. Optimisation
* Changed Mediator GLOBAL Stats from u64 to i64 in case of negative values
* Removed unused common/Stats module
* improved delete_message return type to DeleteMessageResponse Struct, with returns for success and errors
* Renamed send_message() to send_didcomm_message()

### 6th June 2024

* Modified list_messages() to accept a DID (mainly for future use where you could check multiple DID's owned by you)
