# Affinidi Trust Network - Affinidi Trusted Messaging - Processor Service

## Changelog history

### 16th June 2024

* Fixed a bug in store_message where time format was truncating on millisecond values < 100

### 9th June 2024

* Fixed a bug in store_message redis Lua function where stream ID's were in seconds and not milliseconds.

### 7th June 2024

* Added delete_message Lua function

### 6th June 2024

* Added store_message Lua function
