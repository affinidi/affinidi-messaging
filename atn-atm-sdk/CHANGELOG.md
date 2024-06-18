# Affinidi Trust Network - Affinidi Trusted Messaging - Software Development Kit

## Changelog history

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
