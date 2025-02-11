# Affinidi Messaging Processor

Tasks that can be run as a parallel task within the Mediator, or run externally as a stand-alone service.

This provides scalability by being able to distribute heavy tasks away from the core Mediator functionality

## Processors

### Message Expiry Cleanup

Cleans up expired messages by removing them from the database based on expiry headers

### Forwarding

Handles the routing/forwarding of a DIDComm message to a 3rd party Mediator/DIDComm-Agent **This is a work in progress**
