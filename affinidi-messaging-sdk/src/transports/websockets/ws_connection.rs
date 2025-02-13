/*!
A per Profile WebSocket connection to a DIDComm Mediator.

These connections are managed by the `WsHandler` and are created and destroyed as needed.

Each WsConnection is a tokio parallel task, and responsible for unpacking incoming messages

*/
use super::SharedState;
use crate::{errors::ATMError, profiles::Profile, protocols::Protocols, ATM};
use affinidi_messaging_didcomm::{Message as DidcommMessage, UnpackMetadata};
use futures_util::SinkExt;
use http::header::AUTHORIZATION;
use std::{sync::Arc, time::Duration};
use tokio::{
    net::TcpStream,
    select,
    sync::mpsc::{Receiver, Sender},
    task::JoinHandle,
    time::sleep,
};
use tokio_stream::StreamExt;
use tokio_tungstenite::{
    connect_async_tls_with_config,
    tungstenite::{
        client::IntoClientRequest, error::ProtocolError, protocol::frame::Utf8Bytes,
        Error as ws_error, Message,
    },
    MaybeTlsStream, WebSocketStream,
};
use tracing::{debug, warn, error, span, Instrument};

/// Commands between the websocket handler and the websocket connections
#[derive(Debug)]
pub(crate) enum WsConnectionCommands {
    // From Handler (or SDK)
    Send(String), // Sends the message string to the websocket
    Stop,         // Stops the connection
    /// Enables direct channel for this profile
    EnableDirectChannel(Sender<Box<(DidcommMessage, UnpackMetadata)>>),
    DisableDirectChannel,
    // To Handler
    Connected(Arc<Profile>, String), // Connection is ready for profile (and status message to retrieve)
    Disconnected(Arc<Profile>), // WebSocket connection is disconnected
    MessageReceived(Box<(DidcommMessage, UnpackMetadata)>),
}

#[derive(Clone, Debug)]
enum State {
    Disconnected,
    Connecting,
    Connected,
}

pub struct WsConnection {
    profile: Arc<Profile>,
    shared: Arc<SharedState>,
    state: State,
    to_handler: Sender<WsConnectionCommands>,
    from_handler: Receiver<WsConnectionCommands>,
    to_connection: Sender<WsConnectionCommands>,
}

impl WsConnection {
    pub(crate) async fn activate(
        shared_state: Arc<SharedState>,
        profile: &Arc<Profile>,
        to_handler: Sender<WsConnectionCommands>,
        from_handler: Receiver<WsConnectionCommands>,
        to_connection: Sender<WsConnectionCommands>,
    ) -> Result<JoinHandle<()>, ATMError> {
        let mut connection = WsConnection {
            profile: profile.clone(),
            shared: shared_state.clone(),
            state: State::Disconnected,
            from_handler,
            to_handler,
            to_connection,
        };
        debug!(
            "Activating websocket connection for profile ({})",
            profile.inner.alias
        );

        let handle = tokio::spawn(async move {
            let _ = connection.run().await;
        });

        Ok(handle)
    }

    async fn run(&mut self) -> Result<(), ATMError> {
        //let alias = { self.profile.read().await.alias.clone() };

        let _span = span!(tracing::Level::DEBUG, "WsConnection::run", profile = %self.profile.inner.alias.clone());

        async move {
            // ATM utility for this connection
            let atm = ATM {
                inner: self.shared.clone(),
            };
            let protocols = Protocols::new();

            let mut web_socket = match self._handle_connection(&atm, &protocols, true).await {
                Ok(ws) => ws,
                Err(e) => {
                    error!("Error creating websocket connection: {:?}", e);
                    return;
                }
            };

            let mut direct_channel: Option<Sender<Box<(DidcommMessage, UnpackMetadata)>>> = None;
           
            loop {
                select! {
                    value = web_socket.next() => {
                        match value { Some(msg) => {
                            match msg {
                                Ok(payload) => {
                                    if payload.is_text() {
                                        match payload.to_text() {
                                            Ok(msg) => {
                                                debug!("Received text message ({})", msg);
                                                let unpack = match atm.unpack(msg).await {
                                                    Ok(unpack) => unpack,
                                                    Err(e) => {
                                                        error!("Error unpacking message: {:?}", e);
                                                        continue;
                                                    }
                                                };
                                                match &direct_channel { 
                                                    Some(sender) => {
                                                        let _ = sender.send(Box::new(unpack)).await;
                                                    } _ => {
                                                        let _ = self.to_handler.send(WsConnectionCommands::MessageReceived(Box::new(unpack))).await;
                                                    }
                                                }
                                            } _ => {
                                                error!("Received non-text message");
                                            }
                                        }
                                    } else if payload.is_close() {
                                        error!("Websocket closed");
                                        let _ = self.to_handler.send(WsConnectionCommands::Disconnected(self.profile.clone())).await;
                                        web_socket = match self._handle_connection(&atm, &protocols, true).await {
                                            Ok(ws) => ws,
                                            Err(e) => {
                                                error!("Error creating websocket connection: {:?}", e);
                                                return;
                                            }
                                        };
                                    } else {
                                        error!("Error getting payload from message: {:?}", payload);
                                        continue;
                                    }
                                }
                                Err(err) => match err {
                                    ws_error::Protocol(ProtocolError::ResetWithoutClosingHandshake) => {
                                        error!("Websocket reset without closing handshake");
                                        let _ = self.to_handler.send(WsConnectionCommands::Disconnected(self.profile.clone())).await;
                                        web_socket = match self._handle_connection(&atm, &protocols, true).await {
                                            Ok(ws) => ws,
                                            Err(e) => {
                                                error!("Error creating websocket connection: {:?}", e);
                                                return;
                                            }
                                        };
                                    }
                                    _ => {
                                        let _ = self.to_handler.send(WsConnectionCommands::Disconnected(self.profile.clone())).await;
                                        error!("Unknown WebSocket Error: {:?}", err);
                                        break;
                                    }
                                }
                            }
                            } _ => {
                                let _ = self.to_handler.send(WsConnectionCommands::Disconnected(self.profile.clone())).await;
                                error!("websocket error : {:?}", value);
                                break;
                            }
                        }
                    }
                    value = self.from_handler.recv() => {
                        match value { Some(cmd) => {
                            match cmd {
                                WsConnectionCommands::Send(msg) => {
                                    debug!("Sending message ({}) to websocket", msg);
                                    match web_socket.send(Message::Text(Utf8Bytes::from(msg))).await {
                                        Ok(_) => {
                                            debug!("Message sent");
                                        }
                                        Err(e) => {
                                            error!("Error sending message: {:?}", e);
                                        }
                                    }
                                }
                                WsConnectionCommands::Stop => {
                                    debug!("Stopping websocket connection");
                                    break;
                                }
                                WsConnectionCommands::EnableDirectChannel(sender) => {
                                    debug!("Enabling direct channel");
                                    direct_channel = Some(sender);
                                }
                                WsConnectionCommands::DisableDirectChannel => {
                                    debug!("Disabling direct channel");
                                    direct_channel = None;
                                }
                                _ => {
                                    println!("Unhandled command");
                                }
                            }
                        } _ => {
                            error!("Error getting command {:#?}", value);
                            continue;
                        }}
                    }
                }
            }
            let _ = self.to_handler.send(WsConnectionCommands::Disconnected(self.profile.clone())).await;
            let _ = web_socket.close(None).await;
            debug!("Websocket connection closed");
        }
        .instrument(_span)
        .await;

        Ok(())
    }

    // Wrapper that handles all of the logic of setting up a connection to the mediator
    async fn _handle_connection(
        &mut self,
        atm: &ATM,
        protocols: &Protocols,
        update_sdk: bool,
    ) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>, ATMError> {
        debug!("Starting websocket connection");

        self.state = State::Connecting;
        let mut delay: u8 = 1;
        let web_socket = loop {
            match self._create_socket().await {
                Ok(ws) => break ws,
                Err(e) => {
                    error!("Error creating websocket connection: {:?}", e);
                    sleep(Duration::from_secs(delay as u64)).await;
                    if delay < 60 {
                        delay *= 2;
                    }
                    if delay > 60 {
                        delay = 60;
                    }
                }
            }
        };

        debug!("Websocket connected");
        {
            // Update the mediator state
            if let Some(mediator) = &*self.profile.inner.mediator {
                mediator
                    .ws_connected
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                *mediator.ws_channel_tx.lock().await = Some(self.to_connection.clone());
            }
        }
        debug!("Mediator state updated to connected");
        self.state = State::Connected;

        // Enable live_streaming on this socket
        let status_id = match protocols
            .message_pickup
            .toggle_live_delivery(atm, &self.profile, true)
            .await
        {
            Ok(status_id) => {
                debug!("Live streaming enabled");
                status_id
            }
            Err(e) => {
                error!("Error enabling live streaming: {:?}", e);
                return Err(ATMError::TransportError(
                    "Error enabling live streaming".to_string(),
                ));
            }
        };

        if update_sdk {
            debug!("channel to SDK = capacity = {}", self.to_handler.capacity());
            match self
                .to_handler
                .try_send(WsConnectionCommands::Connected(
                    self.profile.clone(),
                    status_id,
                )) {
                Ok(_) => {}
                Err(e) => {
                warn!("Channel to WS_handler is full: {:?}", e);
                }
            }
        }

        Ok(web_socket)
    }

    // Responsible for creating a websocket connection to the mediator
    async fn _create_socket(
        &mut self,
    ) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>, ATMError> {
        // Check if authenticated
        let tokens = self.profile.authenticate(&self.shared).await?;

        debug!("Creating websocket connection");
        // Create a custom websocket request, turn this into a client_request
        // Allows adding custom headers later

        let Some(mediator) = &*self.profile.inner.mediator else {
            return Err(ATMError::ConfigError(format!(
                "Profile ({}) is missing a valid mediator configuration!",
                self.profile.inner.alias
            )));
        };

        let Some(address) = &mediator.websocket_endpoint else {
            return Err(ATMError::ConfigError(format!(
                "Profile ({}) is missing a valid websocket endpoint!",
                self.profile.inner.alias
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
        let ws_stream = match connect_async_tls_with_config(
            request,
            None,
            false,
            Some(self.shared.ws_connector.clone()),
        )
        .await
        {
            Ok((ws_stream, _)) => ws_stream,
            Err(e) => {
                return Err(ATMError::TransportError(format!(
                    "Could not connect to websocket. Reason: {}",
                    e
                )))
            }
        };

        debug!("Completed websocket connection");

        Ok(ws_stream)
    }
}
