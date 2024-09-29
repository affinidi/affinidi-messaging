//! Adds and removed administration accounts from the mediator
//! Must be a administrator to use this protocol
use affinidi_messaging_didcomm::Message;

use crate::{
    common::errors::{MediatorError, Session},
    messages::ProcessMessageResponse,
    SharedData,
};

/// Responsible for processing a Mediator Administration message
pub(crate) async fn process(
    msg: &Message,
    state: &SharedData,
    session: &Session,
) -> Result<ProcessMessageResponse, MediatorError> {
    Err(MediatorError::NotImplemented(
        "MediatorLocalACLManagement".into(),
        "process".into(),
    ))
}
