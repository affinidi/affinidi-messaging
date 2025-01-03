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
    protocols::mediator::global_acls::MediatorGlobalACLRequest,
};
use serde_json::{json, Value};
use tracing::{span, warn, Instrument};
use uuid::Uuid;

pub(crate) async fn process(
    msg: &Message,
    state: &SharedData,
    session: &Session,
) -> Result<ProcessMessageResponse, MediatorError> {
    let _span = span!(tracing::Level::DEBUG, "global_acls");

    async move {
         // Check to ensure this account is an admin account
         if !state
         .database
         .check_admin_account(&session.did_hash)
         .await?
     {
         warn!("DID ({}) is not an admin account", session.did_hash);
         return generate_error_response(state, session, &msg.id, ProblemReport::new(
             ProblemReportSorter::Error,
             ProblemReportScope::Protocol,
             "unauthorized".into(),
             "unauthorized to access Mediator Administration protocol. Must be an administrator for this Mediator!".into(),
             vec![], None
         ), false);
     }

     // Parse the message body
     let request: MediatorGlobalACLRequest = match serde_json::from_value(msg.body.clone()) {
         Ok(request) => request,
         Err(err) => {
             warn!("Error parsing Mediator Administration request. Reason: {}", err);
             return generate_error_response(state, session, &msg.id, ProblemReport::new(
                 ProblemReportSorter::Error,
                 ProblemReportScope::Protocol,
                 "invalid_request".into(),
                 "Error parsing Mediator Administration request. Reason: {1}".into(),
                 vec![err.to_string()], None
             ), false);
         }
     };

     // Process the request
     match request {
        MediatorGlobalACLRequest::GetACL(dids) => {
            match  state.database.global_acls_get(&dids, state.config.security.global_acl_mode.clone()).await {
                Ok(response) => {
                    _generate_response_message(&msg.id, &session.did, &state.config.mediator_did, &json!(response))
                }
                Err(err) => {
                    warn!("Error getting global ACLs. Reason: {}", err);
                    generate_error_response(state, session, &msg.id, ProblemReport::new(
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "database_error".into(),
                        "Error getting global ACLs {1}".into(),
                        vec![err.to_string()], None
                    ), false)
                }
            }
        }
     }
    }.instrument(_span).await
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
