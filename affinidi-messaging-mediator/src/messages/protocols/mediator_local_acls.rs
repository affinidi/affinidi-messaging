use affinidi_messaging_didcomm::Message;

use crate::{
    common::errors::MediatorError, database::session::Session, messages::ProcessMessageResponse,
    SharedData,
};

pub(crate) async fn process(
    _msg: &Message,
    _state: &SharedData,
    _session: &Session,
) -> Result<ProcessMessageResponse, MediatorError> {
    Err(MediatorError::NotImplemented(
        "MediatorLocalACLManagement".into(),
        "process".into(),
    ))
}
