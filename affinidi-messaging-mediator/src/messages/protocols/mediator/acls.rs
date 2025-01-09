use std::time::SystemTime;

use crate::{
    common::errors::MediatorError,
    database::session::Session,
    messages::{error_response::generate_error_response, ProcessMessageResponse},
    SharedData,
};
use affinidi_messaging_didcomm::Message;
use affinidi_messaging_sdk::{
    messages::problem_report::{ProblemReport, ProblemReportScope, ProblemReportSorter},
    protocols::mediator::{accounts::AccountType, acls_handler::MediatorACLRequest},
};
use serde_json::{json, Value};
use tracing::{span, warn, Instrument};
use uuid::Uuid;

pub(crate) async fn process(
    msg: &Message,
    state: &SharedData,
    session: &Session,
) -> Result<ProcessMessageResponse, MediatorError> {
    let _span = span!(tracing::Level::DEBUG, "mediator_acls");

    async move {
        // Parse the message body
        let request: MediatorACLRequest = match serde_json::from_value(msg.body.clone()) {
            Ok(request) => request,
            Err(err) => {
                warn!("Error parsing Mediator ACL request. Reason: {}", err);
                return generate_error_response(
                    state,
                    session,
                    &msg.id,
                    ProblemReport::new(
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "invalid_request".into(),
                        "Error parsing Mediator ACL request. Reason: {1}".into(),
                        vec![err.to_string()],
                        None,
                    ),
                    false,
                );
            }
        };

        // Process the request
        match request {
            MediatorACLRequest::GetACL(dids) => {
                // Check permissions and ACLs
                if !check_permissions(session, &dids) {
                    warn!("ACL Request from DID ({}) failed. ", session.did_hash);
                    return generate_error_response(
                        state,
                        session,
                        &msg.id,
                        ProblemReport::new(
                            ProblemReportSorter::Error,
                            ProblemReportScope::Protocol,
                            "permission_error".into(),
                            "Error getting ACLs {1}".into(),
                            vec!["Permission denied".to_string()],
                            None,
                        ),
                        false,
                    );
                }

                match state
                    .database
                    .get_did_acls(&dids, state.config.security.mediator_acl_mode.clone())
                    .await
                {
                    Ok(response) => _generate_response_message(
                        &msg.id,
                        &session.did,
                        &state.config.mediator_did,
                        &json!(response),
                    ),
                    Err(err) => {
                        warn!("Error getting ACLs. Reason: {}", err);
                        generate_error_response(
                            state,
                            session,
                            &msg.id,
                            ProblemReport::new(
                                ProblemReportSorter::Error,
                                ProblemReportScope::Protocol,
                                "database_error".into(),
                                "Error getting ACLs {1}".into(),
                                vec![err.to_string()],
                                None,
                            ),
                            false,
                        )
                    }
                }
            }
        }
    }
    .instrument(_span)
    .await
}

// Helper method that determines if an ACL Request can be processed
// Checks if the account is an admin account (blanket allow/approval)
// If not admin, then ensures we are only operating on the account's own DID
// Returns true if the request can be processed, false otherwise
pub(crate) fn check_permissions(session: &Session, dids: &[String]) -> bool {
    session.account_type == AccountType::RootAdmin
        || session.account_type == AccountType::Admin
        || dids.len() == 1 && dids[0] == session.did
}

/// Helper method that generates a response message
/// - `thid` - The thread ID of the message
/// - `to` - The recipient of the message
/// - `from` - The sender of the message
/// - `value` - The value to send in the message
fn _generate_response_message(
    thid: &str,
    to: &str,
    from: &str,
    value: &Value,
) -> Result<ProcessMessageResponse, MediatorError> {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Build the message
    let response = Message::build(
        Uuid::new_v4().into(),
        "https://affinidi.com/messaging/global-acl-management".to_owned(),
        value.to_owned(),
    )
    .thid(thid.to_owned())
    .to(to.to_owned())
    .from(from.to_owned())
    .created_time(now)
    .expires_time(now + 300)
    .finalize();

    Ok(ProcessMessageResponse {
        store_message: true,
        force_live_delivery: false,
        data: crate::messages::WrapperType::Message(response),
        forward_message: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_permissions_admin_success() {
        let session = Session {
            did: "did:example:123".to_string(),
            account_type: AccountType::Admin,
            ..Default::default()
        };
        let dids = vec!["did:example:123".to_string()];
        assert!(check_permissions(&session, &dids));
    }

    #[test]
    fn test_check_permissions_root_admin_success() {
        let session = Session {
            did: "did:example:123".to_string(),
            account_type: AccountType::RootAdmin,
            ..Default::default()
        };
        let dids = vec!["did:example:1234".to_string()];
        assert!(check_permissions(&session, &dids));
    }

    #[test]
    fn test_check_permissions_standard_success() {
        let session = Session {
            did: "did:example:123".to_string(),
            account_type: AccountType::Standard,
            ..Default::default()
        };
        let dids = vec!["did:example:123".to_string()];
        assert!(check_permissions(&session, &dids));
    }

    #[test]
    fn test_check_permissions_standard_multiple_dids_failure() {
        let session = Session {
            did: "did:example:123".to_string(),
            account_type: AccountType::Standard,
            ..Default::default()
        };
        let dids = vec![
            "did:example:123".to_string(),
            "did:example:hacker".to_string(),
        ];
        assert!(!check_permissions(&session, &dids));
    }

    #[test]
    fn test_check_permissions_standard_wrong_did_failure() {
        let session = Session {
            did: "did:example:123".to_string(),
            account_type: AccountType::Standard,
            ..Default::default()
        };
        let dids = vec!["did:example:1234".to_string()];
        assert!(!check_permissions(&session, &dids));
    }
}
