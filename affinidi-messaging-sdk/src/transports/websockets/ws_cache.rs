/*!
 * Message cache for WebSocket transport
 */
use super::ws_handler::WsHandlerCommands;
use affinidi_messaging_didcomm::{Message, UnpackMetadata};
use std::{collections::HashMap, mem::size_of_val};
use tokio::sync::mpsc::Sender;
use tracing::{debug, warn};

/// Message cache struct
/// Holds live-stream messages in a cache so we can get the first available or by a specific message ID
#[derive(Default)]
pub(crate) struct MessageCache {
    pub(crate) messages: HashMap<String, (Message, UnpackMetadata)>, // Cache of message data, key is the message ID
    pub(crate) thid_lookup: HashMap<String, String>, // Lookup table for thread ID to message ID
    pub(crate) search_list: HashMap<String, Sender<WsHandlerCommands>>, // Search list of message IDs key = ID to look up (could be ID or THID)
    pub(crate) ordered_list: Vec<String>, // Ordered list of message IDs in order as they are received
    pub(crate) total_count: u32,          // Number of messages in cache
    pub(crate) total_bytes: u64, // Total size of messages in cache (approx as based on object size)
    pub(crate) cache_full: bool, // Flag to state that the cache is full
    pub(crate) fetch_cache_limit_count: u32, // Cache limit on # of messages
    pub(crate) fetch_cache_limit_bytes: u64, // Cache limit on total size of messages
    pub(crate) next_flag: bool,  // Used to state that next() was called on an empty cache
}

impl MessageCache {
    pub(crate) fn insert(&mut self, message: Message, meta: UnpackMetadata) {
        self.messages
            .insert(message.id.clone(), (message.clone(), meta));
        self.ordered_list.push(message.id.clone());
        self.total_count += 1;
        self.total_bytes += size_of_val(&message) as u64;
        if self.total_count > self.fetch_cache_limit_count
            || self.total_bytes > self.fetch_cache_limit_bytes
        {
            self.cache_full = true;
        }

        if let Some(thid) = message.thid {
            self.thid_lookup.insert(thid, message.id.clone());
        } else if let Some(pthid) = message.pthid {
            // DIDComm problem reports use pthid only
            self.thid_lookup.insert(pthid, message.id.clone());
        }
        debug!(
            "Message inserted into cache: id({}) cached_count({})",
            message.id, self.total_count
        );
    }

    /// Get the next message from the cache
    pub(crate) fn next(&mut self) -> Option<(Message, UnpackMetadata)> {
        if self.ordered_list.is_empty() {
            self.next_flag = true;
            return None;
        }

        // Get the message ID of the first next message
        let id = self.ordered_list.remove(0);

        self.remove(&id)
    }

    /// Can we find a specific message in the cache?
    /// If not, then we add it to the search list to look up later as messages come in (within the duration of the original get request)
    pub(crate) fn get(
        &mut self,
        msg_id: &str,
        channel: &Sender<WsHandlerCommands>,
    ) -> Option<(Message, UnpackMetadata)> {
        let r = if let Some((message, meta)) = self.messages.get(msg_id) {
            Some((message.clone(), meta.clone()))
        } else if let Some(id) = self.thid_lookup.get(msg_id) {
            if let Some((message, meta)) = self.messages.get(id) {
                Some((message.clone(), meta.clone()))
            } else {
                warn!(
                    "thid_lookup found message ID ({}) but message id ({}) not found in cache",
                    msg_id, id
                );
                None
            }
        } else {
            debug!(
                "Message ID ({}) not found in cache, adding to search list",
                msg_id
            );
            self.search_list.insert(msg_id.to_string(), channel.clone());
            None
        };

        // Remove the message from cache if it was found
        if let Some((message, _)) = &r {
            self.remove(&message.id);
        }
        r
    }

    pub(crate) fn remove(&mut self, msg_id: &str) -> Option<(Message, UnpackMetadata)> {
        // remove the message from the ordered list
        if let Some(pos) = self.ordered_list.iter().position(|r| r == msg_id) {
            self.ordered_list.remove(pos);
        }

        // Remove from search list
        self.search_list.remove(msg_id);

        // Get the message and metadata from the cache
        let (message, meta) = if let Some((message, meta)) = self.messages.remove(msg_id) {
            // Remove this from thid_lookup if it exists
            if let Some(thid) = &message.thid {
                self.thid_lookup.remove(thid);
            } else if let Some(pthid) = &message.pthid {
                self.thid_lookup.remove(pthid);
            }

            (message, meta)
        } else {
            return None;
        };

        self.total_count -= 1;
        self.total_bytes -= size_of_val(&message) as u64;

        // reset cache_full flag
        if self.cache_full
            && (self.total_count <= self.fetch_cache_limit_count
                && self.total_bytes <= self.fetch_cache_limit_bytes)
        {
            self.cache_full = false;
        }

        Some((message, meta))
    }

    /// Search for a message in the cache
    /// If it exists, will remove and return from the cache
    ///
    /// Logic:
    /// Try and find if their is an existing search for the message id/thid/pthid
    pub(crate) fn search(
        &mut self,
        msg_id: &str,
        thid: Option<&str>,
        pthid: Option<&str>,
    ) -> Option<Sender<WsHandlerCommands>> {
        // Can we find a match on thid?
        if let Some(thid) = thid {
            if let Some(channel) = self.search_list.remove(thid) {
                return Some(channel);
            }
        }

        if let Some(pthid) = pthid {
            if let Some(channel) = self.search_list.remove(pthid) {
                return Some(channel);
            }
        }

        self.search_list.remove(msg_id)
    }

    /// Is the cache full based on limits?
    pub(crate) fn is_full(&self) -> bool {
        self.cache_full
    }
}
