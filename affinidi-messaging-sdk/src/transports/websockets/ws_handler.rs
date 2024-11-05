use super::SharedState;
use crate::{errors::ATMError, profiles::Profile, ATM};
use affinidi_messaging_didcomm::{Message, UnpackMetadata};
use std::{
    collections::{HashMap, HashSet},
    mem::size_of_val,
    sync::Arc,
};
use tokio::{
    select,
    sync::{
        mpsc::{self, Receiver, Sender},
        RwLock,
    },
};
use tracing::{debug, info, span, warn, Instrument, Level};

/// Message cache struct
/// Holds live-stream messages in a cache so we can get the first available or by a specific message ID
#[derive(Default)]
struct MessageCache {
    messages: HashMap<String, (Message, UnpackMetadata)>, // Cache of message data, key is the message ID
    thid_lookup: HashMap<String, String>, // Lookup table for thread ID to message ID
    search_list: HashSet<String>, // Search list of message IDs key = ID to look up (could be ID or THID)
    ordered_list: Vec<String>,    // Ordered list of message IDs in order as they are received
    total_count: u32,             // Number of messages in cache
    total_bytes: u64, // Total size of messages in cache (approx as based on object size)
    cache_full: bool, // Flag to state that the cache is full
    fetch_cache_limit_count: u32, // Cache limit on # of messages
    fetch_cache_limit_bytes: u64, // Cache limit on total size of messages
    next_flag: bool,  // Used to state that next() was called on an empty cache
}

impl MessageCache {
    fn insert(&mut self, message: Message, meta: UnpackMetadata) {
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
    fn next(&mut self) -> Option<(Message, UnpackMetadata)> {
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
    fn get(&mut self, msg_id: &str) -> Option<(Message, UnpackMetadata)> {
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
            self.search_list.insert(msg_id.to_string());
            None
        };

        // Remove the message from cache if it was found
        if let Some((message, _)) = &r {
            self.remove(&message.id);
        }
        r
    }

    fn remove(&mut self, msg_id: &str) -> Option<(Message, UnpackMetadata)> {
        // remove the message from thh ordered list
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

    /// Is the cache full based on limits?
    fn is_full(&self) -> bool {
        self.cache_full
    }
}

/// Possible messages that can be sent to the websocket handler
#[derive(Debug)]
pub(crate) enum WsHandlerCommands {
    // Messages sent from SDK to the Handler
    Exit,
    Activate(Arc<RwLock<Profile>>),
    Deactivate(Arc<RwLock<Profile>>),
    Next(Arc<RwLock<Profile>>), // Gets the next message from the cache
    Get(Arc<RwLock<Profile>>, String), // Gets the message with the specified ID from the cache
    TimeOut(Arc<RwLock<Profile>>, String), // SDK request timed out, contains msg_id we were looking for
    // Messages sent from Handler to the SDK
    Started,
    MessageReceived(Message, Box<UnpackMetadata>), // Message received from the websocket
    NotFound,                                      // Message not found in the cache
}

impl ATM {
    /// WebSocket streaming handler
    /// from_sdk is an MPSC channel used to receive messages from the main thread that will be sent to the websocket
    /// to_sdk is an MPSC channel used to send messages to the main thread that were received from the websocket
    /// web_socket is the websocket stream itself which can be used to send and receive messages
    pub(crate) async fn ws_handler(
        shared_state: Arc<RwLock<SharedState>>,
        from_sdk: &mut Receiver<WsHandlerCommands>,
        to_sdk: Sender<WsHandlerCommands>,
    ) -> Result<(), ATMError> {
        let _span = span!(Level::INFO, "ws_handler");
        async move {
            debug!("Starting websocket handler");

            // Set up a message cache
            let mut cache = MessageCache {
                fetch_cache_limit_count: shared_state.read().await.config.fetch_cache_limit_count,
                fetch_cache_limit_bytes: shared_state.read().await.config.fetch_cache_limit_bytes,
                ..Default::default()
            };

            // Set up the channel for WS_Connections to communicate to the handler
        // Create a new channel with a capacity of at most 32. This communicates from WS_Connections to the WS_Handler
        let ( handler_tx, mut handler_rx) = mpsc::channel::<WsHandlerCommands>(32);

            shared_state.read().await.ws_handler_send_stream.send(WsHandlerCommands::Started).await.map_err(|err| {
                ATMError::TransportError(format!("Could not send message to SDK: {:?}", err))
            })?;

            loop {
                select! {
                    value = handler_rx.recv(), if !cache.is_full() => {
                        // do something here
                    }
                    value = from_sdk.recv() => {
                        if let Some(cmd) = value {
                            match cmd {
                                WsHandlerCommands::Next(profile) => {
                                    if let Some((message, meta)) = cache.next() {
                                        to_sdk.send(WsHandlerCommands::MessageReceived(message, Box::new(meta))).await.map_err(|err| {
                                            ATMError::TransportError(format!("Could not send message to SDK: {:?}", err))
                                        })?;
                                    }
                                }
                                WsHandlerCommands::Get(profile, id) => {
                                    if let Some((message, meta)) = cache.get(&id) {
                                        to_sdk.send(WsHandlerCommands::MessageReceived(message, Box::new(meta))).await.map_err(|err| {
                                            ATMError::TransportError(format!("Could not send message to SDK: {:?}", err))
                                        })?;
                                    } else {
                                        to_sdk.send(WsHandlerCommands::NotFound).await.map_err(|err| {
                                            ATMError::TransportError(format!("Could not send message to SDK: {:?}", err))
                                        })?;
                                    }
                                }
                                WsHandlerCommands::Exit => {
                                    debug!("Received EXIT message, closing channels");
                                    break;
                                }
                                WsHandlerCommands::TimeOut(profile, id) => {
                                    cache.search_list.remove(&id);
                                }
                                _ => {
                                    debug!("Received unknown command");
                                }
                            }
                        } else {
                            info!("Channel Closed");
                            break;
                        }
                    }
                }
            }

            from_sdk.close();

            debug!("Channel closed, stopping websocket handler");
            Ok(())
        }
        .instrument(_span)
        .await
    }
}
