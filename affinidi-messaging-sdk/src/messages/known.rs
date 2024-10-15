//! Helper functions to determine message type

use std::str::FromStr;

use crate::errors::ATMError;

pub enum MessageType {
    AffinidiAuthenticate,            // Affinidi Messaging Authentication Response
    ForwardRequest,                  // DidComm Routing 2.0 Forward Request
    MediatorAdministration,          // Mediator Administration Protocol
    MediatorGlobalACLManagement,     // Mediator Global ACL Management Protocol
    MediatorLocalACLManagement,      // Mediator Global ACL Management Protocol
    MessagePickupStatusRequest,      // Message Pickup 3.0 Status Request
    MessagePickupDeliveryRequest,    // Message Pickup 3.0 Delivery Request
    MessagePickupMessagesReceived,   // Message Pickup 3.0 Messages Received (ok to delete)
    MessagePickupLiveDeliveryChange, // Message Pickup 3.0 Live-delivery-change (Streaming enabled)
    ProblemReport,                   // Problem Report Protocol
    TrustPing,                       // Trust Ping Protocol
    Other(String),                   // Other message type
}

impl FromStr for MessageType {
    type Err = ATMError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "https://didcomm.org/trust-ping/2.0/ping" => Ok(Self::TrustPing),
            "https://affinidi.com/atm/1.0/authenticate" => Ok(Self::AffinidiAuthenticate),
            "https://didcomm.org/mediator/1.0/admin-management" => Ok(Self::MediatorAdministration),
            "https://didcomm.org/mediator/1.0/global-acl-management" => {
                Ok(Self::MediatorGlobalACLManagement)
            }
            "https://didcomm.org/mediator/1.0/local-acl-management" => {
                Ok(Self::MediatorLocalACLManagement)
            }
            "https://didcomm.org/messagepickup/3.0/status-request" => {
                Ok(Self::MessagePickupStatusRequest)
            }
            "https://didcomm.org/messagepickup/3.0/live-delivery-change" => {
                Ok(Self::MessagePickupLiveDeliveryChange)
            }
            "https://didcomm.org/messagepickup/3.0/delivery-request" => {
                Ok(Self::MessagePickupDeliveryRequest)
            }
            "https://didcomm.org/messagepickup/3.0/messages-received" => {
                Ok(Self::MessagePickupMessagesReceived)
            }
            "https://didcomm.org/routing/2.0/forward" => Ok(Self::ForwardRequest),
            "https://didcomm.org/report-problem/2.0/problem-report" => Ok(Self::ProblemReport),
            _ => Ok(Self::Other(s.to_string())),
        }
    }
}