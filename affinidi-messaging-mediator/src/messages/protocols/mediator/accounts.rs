use std::time::SystemTime;

use affinidi_messaging_didcomm::Message;
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_sdk::{
    messages::problem_report::{ProblemReport, ProblemReportScope, ProblemReportSorter},
    protocols::mediator::{
        accounts::{AccountType, MediatorAccountRequest},
        acls::{AccessListModeType, MediatorACLSet},
    },
};
use serde_json::{Value, json};
use sha256::digest;
use tracing::{Instrument, debug, info, span, warn};
use uuid::Uuid;

use crate::{
    SharedData,
    database::session::Session,
    messages::{ProcessMessageResponse, error_response::generate_error_response},
};

use super::acls::check_permissions;

pub(crate) async fn process(
    msg: &Message,
    state: &SharedData,
    session: &Session,
) -> Result<ProcessMessageResponse, MediatorError> {
    let _span = span!(tracing::Level::DEBUG, "mediator_accounts");

    async move {
        // Parse the message body
        let request: MediatorAccountRequest = match serde_json::from_value(msg.body.clone()) {
            Ok(request) => request,
            Err(err) => {
                warn!(
                    "Error parsing Mediator Account request. Reason: {}",
                    err
                );
                return generate_error_response(
                    state,
                    session,
                    &msg.id,
                    ProblemReport::new(
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "invalid_request".into(),
                        "Error parsing Mediator Account request. Reason: {1}".into(),
                        vec![err.to_string()],
                        None,
                    ),
                    false,
                );
            }
        };

        // Process the request
        match request {
            MediatorAccountRequest::AccountGet(did_hash) => {
                // Check permissions and ACLs
                if !check_permissions(session, &[did_hash.clone()]) {
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

                match state.database.account_get(&did_hash).await {
                    Ok(response) => _generate_response_message(
                        &msg.id,
                        &session.did,
                        &state.config.mediator_did,
                        &json!(response),
                    ),
                    Err(err) => {
                        warn!("Error listing accounts. Reason: {}", err);
                        generate_error_response(
                            state,
                            session,
                            &msg.id,
                            ProblemReport::new(
                                ProblemReportSorter::Error,
                                ProblemReportScope::Protocol,
                                "database_error".into(),
                                "Error listing accounts {1}".into(),
                                vec![err.to_string()],
                                None,
                            ),
                            false,
                        )
                    }
                }
            }
            MediatorAccountRequest::AccountList { cursor, limit } => {
                if !(session.account_type == AccountType::Admin || session.account_type == AccountType::RootAdmin) {
                    warn!("DID ({}) is not an admin account", session.did_hash);
                    return generate_error_response(
                        state,
                        session,
                        &msg.id,
                        ProblemReport::new(
                            ProblemReportSorter::Error,
                            ProblemReportScope::Protocol,
                            "unauthorized".into(),
                            "unauthorized to access Mediator Account protocol. Must be an administrator for this Mediator!".into(),
                            vec![],
                            None,
                        ),
                        false,
                    );
                }

                match state.database.account_list(cursor, limit).await {
                    Ok(response) => _generate_response_message(
                        &msg.id,
                        &session.did,
                        &state.config.mediator_did,
                        &json!(response),
                    ),
                    Err(err) => {
                        warn!("Error listing accounts. Reason: {}", err);
                        generate_error_response(
                            state,
                            session,
                            &msg.id,
                            ProblemReport::new(
                                ProblemReportSorter::Error,
                                ProblemReportScope::Protocol,
                                "database_error".into(),
                                "Error listing accounts {1}".into(),
                                vec![err.to_string()],
                                None,
                            ),
                            false,
                        )
                    }
                }
            }
            MediatorAccountRequest::AccountAdd {did_hash, acls } => {
                // Check permissions and ACLs
                // 1. Is mediator in explicit_allow mode and is the requestor an ADMIN?
                if state.config.security.mediator_acl_mode == AccessListModeType::ExplicitAllow && !(session.account_type == AccountType::Admin || session.account_type == AccountType::RootAdmin) {
                    warn!("DID ({}) is not an admin account", session.did_hash);
                    return generate_error_response(
                        state,
                        session,
                        &msg.id,
                        ProblemReport::new(
                            ProblemReportSorter::Error,
                            ProblemReportScope::Protocol,
                            "unauthorized".into(),
                            "unauthorized to create new accounts. Must be an administrator for this Mediator!".into(),
                            vec![],
                            None,
                        ),
                        false,
                    );
                }

                // 2. Setup the ACLs correctly if not an admin account
                let acls = if session.account_type == AccountType::Admin || session.account_type == AccountType::RootAdmin {
                    if let Some(acls) = acls {
                        MediatorACLSet::from_u64(acls)
                    } else {
                        state.config.security.global_acl_default.clone()
                    }
                } else {
                    state.config.security.global_acl_default.clone()
                };

                match state
                    .database
                    .account_add(&did_hash, &acls, None)
                    .await
                {
                    Ok(response) => _generate_response_message(
                        &msg.id,
                        &session.did,
                        &state.config.mediator_did,
                        &json!(response),
                    ),
                    Err(err) => {
                        warn!("Error adding account. Reason: {}", err);
                        generate_error_response(
                            state,
                            session,
                            &msg.id,
                            ProblemReport::new(
                                ProblemReportSorter::Error,
                                ProblemReportScope::Protocol,
                                "database_error".into(),
                                "Error adding account {1}".into(),
                                vec![err.to_string()],
                                None,
                            ),
                            false,
                        )
                    }
                }
            }
            MediatorAccountRequest::AccountRemove(did_hash) => {
                // Check permissions and ACLs
                if !check_permissions(session, &[did_hash.clone()]) {
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

                // Check if the mediator DID is being removed
                // Protects accidentally deleting the mediator itself
                if state.config.mediator_did_hash == did_hash {
                    return generate_error_response(
                        state,
                        session,
                        &msg.id,
                        ProblemReport::new(
                            ProblemReportSorter::Error,
                            ProblemReportScope::Protocol,
                            "invalid_request".into(),
                            "Error removing account. Cannot remove the Mediator DID".into(),
                            vec![],
                            None,
                        ),
                        false,
                    );
                }

                // Check if the root admin DID is being removed
                // Protects accidentally deleting the only admin account
                let root_admin = digest(&state.config.admin_did);
                if root_admin == did_hash {
                    return generate_error_response(
                        state,
                        session,
                        &msg.id,
                        ProblemReport::new(
                            ProblemReportSorter::Error,
                            ProblemReportScope::Protocol,
                            "invalid_request".into(),
                            "Error removing account. Cannot remove root admin account".into(),
                            vec![],
                            None,
                        ),
                        false,
                    );
                }
                match state.database.account_remove(session,&did_hash, false, false).await {
                    Ok(response) => _generate_response_message(
                        &msg.id,
                        &session.did,
                        &state.config.mediator_did,
                        &json!(response),
                    ),
                    Err(err) => {
                        warn!("Error removing account. Reason: {}", err);
                        generate_error_response(
                            state,
                            session,
                            &msg.id,
                            ProblemReport::new(
                                ProblemReportSorter::Error,
                                ProblemReportScope::Protocol,
                                "database_error".into(),
                                "Error removing account {1}".into(),
                                vec![err.to_string()],
                                None,
                            ),
                            false,
                        )
                    }
                }
            }
            MediatorAccountRequest::AccountChangeType {did_hash, _type } => {
                // Must be an admin level account to change this
                if !state.database.check_admin_account(&session.did_hash).await? {
                    warn!("DID ({}) is not an admin account", session.did_hash);
                    return generate_error_response(state, session, &msg.id, ProblemReport::new(
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "unauthorized".into(),
                        "unauthorized to change account type. Must be an administrator for this Mediator!".into(),
                        vec![], None
                    ), false);
                }

                // Get current account type and handle any shift to/from admin
                let current = state.database.account_get(&did_hash).await?;
                if let Some(current) = &current {
                    if current._type == _type {
                        // Types are the same, no need to change.
                        return _generate_response_message(
                            &msg.id,
                            &session.did,
                            &state.config.mediator_did,
                            &json!(true),
                        );
                    } else if current._type.is_admin() && _type.is_admin() {
                        // Changing between different admin types is ok
                        debug!("Switching admin type for DID: {} from ({}) to ({})", did_hash, current._type, _type);
                    } else if current._type.is_admin() && !_type.is_admin() {
                        // Need to strip admin rights first
                        state.database.strip_admin_accounts(vec![did_hash.clone()]).await?;
                    } else if !current._type.is_admin() && _type.is_admin() {
                        // Need to add admin rights
                        state.database.setup_admin_account(&did_hash, _type, &MediatorACLSet::from_u64(current.acls)).await?;
                        info!("Added admin ({}) rights to DID: {}", _type, did_hash);
                        return _generate_response_message(
                            &msg.id,
                            &session.did,
                            &state.config.mediator_did,
                            &json!(true),
                        );
                    }
                }

                // If here, then it is a simple type change at this point

                match state.database.account_change_type(&did_hash, &_type).await {
                    Ok(_) => {
                        let current_type = if let Some(current) = &current {
                            current._type.to_string()
                        } else {
                            "Unknown".to_string()
                        };
                        info!("Changed account type for DID: ({}) from ({}) to ({})", did_hash, current_type, _type);
                        _generate_response_message(
                        &msg.id,
                        &session.did,
                        &state.config.mediator_did,
                        &json!(true),
                    )}
                    Err(err) => {
                        warn!("Error Changing account type. Reason: {}", err);
                        generate_error_response(
                            state,
                            session,
                            &msg.id,
                            ProblemReport::new(
                                ProblemReportSorter::Error,
                                ProblemReportScope::Protocol,
                                "database_error".into(),
                                "Error changing account type. Reason: {1}".into(),
                                vec![err.to_string()],
                                None,
                            ),
                            false,
                        )
                    }
                }
            }
            MediatorAccountRequest::AccountChangeQueueLimit {did_hash, queue_limit } => {
                 // Check permissions and ACLs
                 if !check_permissions(session, &[did_hash.clone()]) {
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

                let queue_limit = if let Some(ql) = queue_limit {
                    if session.account_type == AccountType::Admin || session.account_type == AccountType::RootAdmin {
                        queue_limit
                    } else  if ql > state.config.limits.queued_messages_hard {
                        Some(state.config.limits.queued_messages_hard)
                    } else {
                        queue_limit
                    }
                } else {
                    None
                };

                match state.database.account_change_queue_limit(&did_hash, queue_limit).await {
                    Ok(_) => {
                        info!("Changed account queue_limit for DID: ({}) to ({:?})", did_hash, queue_limit);
                        _generate_response_message(
                        &msg.id,
                        &session.did,
                        &state.config.mediator_did,
                        &json!(queue_limit),
                    )}
                    Err(err) => {
                        warn!("Error Changing account type. Reason: {}", err);
                        generate_error_response(
                            state,
                            session,
                            &msg.id,
                            ProblemReport::new(
                                ProblemReportSorter::Error,
                                ProblemReportScope::Protocol,
                                "database_error".into(),
                                "Error changing account type. Reason: {1}".into(),
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
        "https://didcomm.org/mediator/1.0/account-management".to_owned(),
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
