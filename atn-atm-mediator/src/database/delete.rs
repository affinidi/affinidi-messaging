use super::DatabaseHandler;
use crate::common::errors::MediatorError;
use atn_atm_sdk::messages::list::{MessageList, MessageListElement};
use redis::Value;
use sha256::digest;
use tracing::{debug, event, span, Instrument, Level};

impl DatabaseHandler {
    /// Deletes a message in the database
    /// Step 1. Retrieve message metadata from MESSAGE_STORE
    /// step 2a. Check if the message is meant for the session owner
    /// Step 2b. Check that the deleted message belongs to the session owner
    ///          I.e. the from_did_hash matches the session DID hash
    /// Step 2c. If message is neither for the session owner nor from the session owner, return an error
    ///
    /// Step 3: Retrieve the SEND_Q and RECEIVE_Q stream_id for the message
    ///
    /// Step 4: Create a transaction
    /// Step 5: Delete the message from MESSAGE_STORE
    /// Step 6: Delete the message META_DATA from MESSAGE_STORE
    /// Step 8: Delete the sender in the SEND_Q_<DID_HASH> LIST (this may not be required if anonymous sender)
    /// Step 9: Update DID_<hash> for sender stats
    /// Step 10: Create a pointer in the EXPIRY_LIST List
    /// Step 11: Update DID_<hash> for recipient stats
    /// Step 12: Update DID_LIST (Hash) for mapping of DID/hash values
    /// Step 13: Create a pointer in the RECEIVE_Q_<DID_HASH> Stream
    /// Step 14: Commit the transaction
    ///
    /// Step 7: Decrement the MESSAGE_STORE bytes_stored field

    pub async fn delete_messages(
        &self,
        session_id: &str,
        did: &str,
        message_hash: &str,
    ) -> Result<MessageListElement, MediatorError> {
        let _span = span!(Level::DEBUG, "delete_messages", message_hash = message_hash);
        async move {
            // step 1. Retrieve message metadata from MESSAGE_STORE
            let metadata = self.get_message_metadata(session_id, message_hash).await?;
            let did_hash = digest(did.as_bytes());

            // step 2. Check if the session_did has ownership of this message???
            if metadata.to_did_hash == did_hash {
                debug!("Message is for the session owner");
            } else if let Some(from) = metadata.from_did_hash.clone() {
                if from == did_hash {
                    debug!("Message is from the session owner");
                } else {
                    // This message is neither for the session owner nor from the session owner
                    // We can't delete this message
                    return Err(MediatorError::PermissionError(
                        session_id.into(),
                        "trying to delete a message that doesn't belong to the session owner"
                            .into(),
                    ));
                }
            } else {
                // This is referring to an anonymous sender
                // We can't validate the sender so we need to return an error
                return Err(MediatorError::AnonymousMessageError(
                    session_id.into(),
                    "trying to delete an anonymous message, can't prove ownership.".into(),
                ));
            }

            // We have the right ownership to delete the message

            let mut conn = self.get_connection().await?;

            // Step 4: Create a transaction
            let mut tx = deadpool_redis::redis::pipe();

            tx.atomic()
                // Step 5: Delete the message from MESSAGE_STORE
                .cmd("HDEL")
                .arg("MESSAGE_STORE")
                .arg(message_hash)
                // Step 6: Delete the message META_DATA from MESSAGE_STORE
                .cmd("HDEL")
                .arg(["META_DATA:", message_hash].concat());

            // Step 8: Delete the sender in the SEND_Q_<DID_HASH> LIST (this may not be required if anonymous sender)
            if let Some(from) = &metadata.from_did_hash {
                tx.cmd("XDEL")
                    .arg(format!("SEND_Q_{}", from))
                    .arg(message_hash);
            }
            // Step 7: Store the sender in the SEND_Q_<DID_HASH> LIST (this may not be required if anonymous sender)
            tx.query_async(&mut conn).await.map_err(|err| {
                event!(
                    Level::ERROR,
                    "Couldn't delete message_id({}) from database for DID {}: {}",
                    message_hash,
                    did,
                    err
                );
                MediatorError::DatabaseError(
                    did.into(),
                    format!(
                        "Couldn't delete message_id({}) from database for DID {}: {}",
                        message_hash, did, err
                    ),
                )
            })?;
            /*
                        // 2nd stage commit
                         // Step 7: Decrement the MESSAGE_STORE bytes_stored field
                         .cmd("HINCRBY")
                         .arg("MESSAGE_STORE")
                         .arg("bytes_stored")
                         .arg(-(metadata.bytes as i64));
            */
            Ok(MessageListElement::default())
        }
        .instrument(_span)
        .await
    }
}
