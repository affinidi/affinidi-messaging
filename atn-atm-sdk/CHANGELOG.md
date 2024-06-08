# Affinidi Trust Network - Affinidi Trusted Messaging - Software Development Kit

## Changelog history

### 8th June 2024

* Refactored namespace for several SDK structs
* implemented get_messages()
* implemented unpack()

### 7th June 2024

* improved delete_message return type to DeleteMessageResponse Struct, with returns for success and errors
* Changed send_ping() so that instead of anonymous field, it is now signed field. Easier to logically think of.
* Added README Documentation
* Modified DeleteMessageResponse from successful to success

### 6th June 2024

* Modified list_messages() to send the requested did as part of the request.
