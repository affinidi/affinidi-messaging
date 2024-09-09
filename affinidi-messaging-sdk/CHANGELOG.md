# Affinidi Trust Network - Affinidi Trusted Messaging - Software Development Kit

## Changelog history

### 3rd Sept 2024 (v0.1.3)

* Added the ability create a affinidi-did-resolver-cache outside of the affinidi-messaging-sdk and share it the ATM SDK
  * Allows for sharing of DID cache inside and outside of ATM for efficiency.

### 2nd Sept 2024 (v0.1.2)

* Added DIDComm pack_* methods so you can pack/unpack directly using the ATM-SDK
* pack_encrypted() - encrypted and optionally signed message
* pack_signed() - plaintext and signed message
* pack_plaintext() - plaintext! not encrypted, not signed
* unpack() - unpacks any format DIDComm message
* NOTE: You are responsible for sending this message to the mediator as a separate step.
*        HTTP(S)   : Call atm.send.didcomm_message(&message, true|false)
*        WebSocket : Call atm.ws-send_didcomm_message(&message, &message_id)

### 20th July 2024

* Message Pickup Message-Delivery and Messages Received implemented

### 18th July 2024

* Message Pickup live-streaming implemented
* Ability to call next() and get() on websocket
* WebSocket cache implemented

### 29th June 2024

* Added ability to pre-load secrets when creating a new ATM client
* This fixes an issue where WebSocket auth requires secrets to be loaded before trying to start
* Implemented Message-Pickup protocol - Status-Request

### 15th June 2024

* get_websocket() function added to ATM
* ATMWebSocket is now a child struct that allows for websocket specific calls

### 13th June 2024

* Adding Secured WebSockets support
* Refactored how SSL certificates are loaded by the SDK
  * HTTP(S) requests use a different SSL/TLS Certificate model than WebSockets
  * Internal change within SDK only. No change to client side code

### 12th June 2024

* Allow option to disable SSL via config

### 9th June 2024

* Minor refactoring of unpack()
* Refactored send_didcomm_message() so it now returns more relevant information such as recipients, message_ids and errors
* refactored send_ping() so it returns new structure
* Changed example ping to now just do a full trust-ping to ATM, includes timing data
* Added new example `demo` to show all API calls

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
