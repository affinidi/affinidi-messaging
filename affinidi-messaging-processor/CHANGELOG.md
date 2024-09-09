# Affinidi Trust Network - Affinidi Trusted Messaging - Processor Service

## Changelog history

### 24th June 2024

* Adding websocket clean_start_streaming() function. This removes any existing session details.

### 20th June 2024

* Changed delete_message() so it updates GLOBAL metric DELETED_BYTES

### 16th June 2024

* Fixed a bug in store_message where time format was truncating on millisecond values < 100

### 9th June 2024

* Fixed a bug in store_message redis Lua function where stream ID's were in seconds and not milliseconds.

### 7th June 2024

* Added delete_message Lua function

### 6th June 2024

* Added store_message Lua function
