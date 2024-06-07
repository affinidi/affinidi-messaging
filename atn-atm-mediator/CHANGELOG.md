# Affinidi Trust Network - Affinidi Trusted Messaging - Mediator Service

## Changelog history

### 7th June 2024

* Added authentication check on database session.state, protects against replay attack.

### 6th June 2024

* Modified list_messages() to accept a DID (mainly for future use where you could check multiple DID's owned by you)
