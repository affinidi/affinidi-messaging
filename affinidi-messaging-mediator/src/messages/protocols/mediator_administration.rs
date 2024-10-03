//! Adds and removed administration accounts from the mediator
//! Must be a administrator to use this protocol
use affinidi_messaging_didcomm::Message;
use affinidi_messaging_sdk::messages::problem_report::{
    ProblemReport, ProblemReportScope, ProblemReportSorter,
};
use tracing::{span, warn, Instrument};

use crate::{
    common::errors::{MediatorError, Session},
    messages::{error_response::generate_error_response, ProcessMessageResponse},
    SharedData,
};

/// Responsible for processing a Mediator Administration message
pub(crate) async fn process(
    msg: &Message,
    state: &SharedData,
    session: &Session,
) -> Result<ProcessMessageResponse, MediatorError> {
    let _span = span!(tracing::Level::DEBUG, "mediator_administration");

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
    //let request: MediatorRequest = serde_json::from_value(msg.body.clone())?;

    generate_error_response(state, session, &msg.id, ProblemReport::new(
        ProblemReportSorter::Error,
        ProblemReportScope::Protocol,
        "not-implemented".into(),
        "Not Implemented".into(),
        vec![], None
    ), false)
}.instrument(_span).await
}
