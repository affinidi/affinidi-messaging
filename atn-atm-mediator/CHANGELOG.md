# Affinidi Trust Network - Affinidi Trusted Messaging - Mediator Service

## Changelog history

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
