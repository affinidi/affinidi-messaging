/*!
A per Profile WebSocket connection to a DIDComm Mediator.
*/
use std::sync::Arc;

use super::SharedState;
use crate::{errors::ATMError, profiles::Profile};
use http::header::AUTHORIZATION;
use tokio::{
    net::TcpStream,
    sync::{
        mpsc::{Receiver, Sender},
        RwLock,
    },
    task::JoinHandle,
};
use tokio_tungstenite::{
    connect_async_tls_with_config, tungstenite::client::IntoClientRequest, MaybeTlsStream,
    WebSocketStream,
};
use tracing::debug;

/// Commands between the websocket handler and the websocket connections
#[derive(Debug)]
pub(crate) enum WsConnectionCommands {
    // From Handler (or SDK)
    Stop,         // Exits the websocket handler
    Send(String), // Sends the message string to the websocket
    // To Handler
    Started,       // Signals that the websocket handler has started
    Error(String), // Error from websocket to be passed back to client
}

#[derive(Clone, Debug)]
enum State {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
}

pub struct WsConnection {
    profile: String,
    shared: Arc<RwLock<SharedState>>,
    state: State,
    url: String,
    from_handler: Receiver<WsConnectionCommands>,
    to_handler: Sender<WsConnectionCommands>,
}

impl WsConnection {
    pub(crate) async fn new(
        shared_state: &Arc<RwLock<SharedState>>,
        profile: &Profile,
        to_handler: Sender<WsConnectionCommands>,
        from_handler: Receiver<WsConnectionCommands>,
    ) -> Result<JoinHandle<()>, ATMError> {
        let Some(mediator) = &profile.mediator else {
            return Err(ATMError::ConfigError(format!(
                "Profile ({}) is missing a valid mediator configuration!",
                profile.alias
            )));
        };

        let Some(url) = &mediator.websocket_endpoint else {
            return Err(ATMError::ConfigError(format!(
                "Profile ({}) is missing a valid websocket endpoint!",
                profile.alias
            )));
        };

        let mut connection = WsConnection {
            profile: profile.alias.clone(),
            shared: shared_state.clone(),
            state: State::Disconnected,
            url: url.to_string(),
            from_handler,
            to_handler,
        };

        Ok(tokio::spawn(async move {
            let _ = WsConnection::run(&mut connection).await;
        }))
    }

    async fn run(connection: &mut WsConnection) {
        let mut connected: bool = false;
        let websocket = WsConnection::_create_socket(connection).await;

        /*
            loop {
                select! {
                    value = web_socket.next(), if !cache.is_full() => {
                        if let Some(msg) = value {
                            if let Ok(payload) = msg {
                                if payload.is_text() {
                                    if let Ok(msg) = payload.to_text() {
                                        debug!("Received text message ({})", msg);
                                        let (message, meta) = match shared_state.unpack(msg).await {
                                            Ok((msg, meta)) => (msg, meta),
                                            Err(err) => {
                                                error!("Error unpacking message: {:?}", err);
                                                continue;
                                            }
                                        };
                                        // Check if we are searching for this message via a get request
                                        if let Some(thid) = &message.thid {
                                            if cache.search_list.contains(thid) {
                                                cache.remove(thid);
                                                to_sdk.send(WSCommand::MessageReceived(message.clone(), Box::new(meta.clone()))).await.map_err(|err| {
                                                    ATMError::TransportError(format!("Could not send message to SDK: {:?}", err))
                                                })?;
                                            }
                                        } else if let Some(pthid) = &message.pthid {
                                            if cache.search_list.contains(pthid) {
                                                cache.remove(pthid);
                                                to_sdk.send(WSCommand::MessageReceived(message.clone(), Box::new(meta.clone()))).await.map_err(|err| {
                                                    ATMError::TransportError(format!("Could not send message to SDK: {:?}", err))
                                                })?;
                                            }
                                        } else if cache.search_list.contains(&message.id) {
                                            to_sdk.send(WSCommand::MessageReceived(message.clone(), Box::new(meta.clone()))).await.map_err(|err| {
                                                ATMError::TransportError(format!("Could not send message to SDK: {:?}", err))
                                            })?;
                                            cache.remove(&message.id);
                                        }

                                        // Send the message to the SDK if next_flag is set
                                        if cache.next_flag {
                                            cache.next_flag = false;
                                            to_sdk.send(WSCommand::MessageReceived(message, Box::new(meta))).await.map_err(|err| {
                                                ATMError::TransportError(format!("Could not send message to SDK: {:?}", err))
                                            })?;
                                        } else {
                                            // Add to cache
                                            cache.insert(message, meta);
                                        }
                                    } else {
                                        error!("Error getting text from message")
                                    }
                                } else {
                                    error!("Received non-text message");
                                }
                            } else {
                                error!("Error getting payload from message");
                                continue;
                            }
                        } else {

                            error!("Error getting message");
                            break;
                        }
                    }
        }
        */
    }

    /// Responsible for creating a websocket connection to the mediator
    async fn _create_socket(
        &mut self,
    ) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>, ATMError> {
        // Check if authenticated
        let (profile, tokens) = {
            let lock = self.shared.write().await;
            let Some(profile) = lock.profiles.get(&self.profile) else {
                return Err(ATMError::ConfigError(format!(
                    "Profile ({}) not found!",
                    self.profile
                )));
            };

            let mut _profile = profile.write().await;
            let tokens = _profile.authenticate(&self.shared).await?;

            (profile.clone(), tokens)
        };

        debug!("Creating websocket connection");
        // Create a custom websocket request, turn this into a client_request
        // Allows adding custom headers later

        let _profile = profile.read().await;
        let Some(mediator) = &_profile.mediator else {
            return Err(ATMError::ConfigError(format!(
                "Profile ({}) is missing a valid mediator configuration!",
                _profile.alias
            )));
        };

        let Some(address) = &mediator.websocket_endpoint else {
            return Err(ATMError::ConfigError(format!(
                "Profile ({}) is missing a valid websocket endpoint!",
                _profile.alias
            )));
        };

        let mut request = address.into_client_request().map_err(|e| {
            ATMError::TransportError(format!("Could not create websocket request. Reason: {}", e))
        })?;

        // Add the Authorization header to the request
        let headers = request.headers_mut();
        headers.insert(
            AUTHORIZATION,
            format!("Bearer {}", tokens.access_token)
                .parse()
                .map_err(|e| {
                    ATMError::TransportError(format!("Could not set Authorization header: {:?}", e))
                })?,
        );

        // Connect to the websocket
        let ws_stream = connect_async_tls_with_config(
            request,
            None,
            false,
            Some(self.shared.read().await.ws_connector.clone()),
        )
        .await
        .expect("Failed to connect")
        .0;

        debug!("Completed websocket connection");

        Ok(ws_stream)
    }
}
