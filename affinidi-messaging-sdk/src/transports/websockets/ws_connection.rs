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
use std::sync::Arc;
use tokio::{
    net::TcpStream,
    select,
    sync::mpsc::{Receiver, Sender},
    task::JoinHandle,
};
use tokio_stream::StreamExt;
use tokio_tungstenite::{
    connect_async_tls_with_config,
    tungstenite::{client::IntoClientRequest, Message},
    MaybeTlsStream, WebSocketStream,
};
use tracing::{debug, error, span, Instrument};

/// Commands between the websocket handler and the websocket connections
#[derive(Debug)]
pub(crate) enum WsConnectionCommands {
    // From Handler (or SDK)
    Send(String), // Sends the message string to the websocket
    Stop,         // Stops the connection
    // To Handler
    Connected(Arc<Profile>, String), // Connection is ready for profile (and status message to retrieve)
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

        let _span = span!(tracing::Level::DEBUG, "WsConnection::run",);

        async move {
            // ATM utility for this connection
            let atm = ATM {
                inner: self.shared.clone(),
            };
            let protocols = Protocols::new();

            debug!("Starting websocket connection");

            self.state = State::Connecting;
            let mut web_socket = self._create_socket().await.unwrap();
            // TODO: Need to implement a recovery here
            debug!("Websocket connected");
            {
                // Update the mediator state
                if let Some(mediator) = &*self.profile.inner.mediator {
                    mediator.ws_connected.store(true, std::sync::atomic::Ordering::Relaxed);
                    *mediator.ws_channel_tx.lock().await = Some(self.to_connection.clone());
                }
            }
            debug!("Mediator state updated to connected");
            self.state = State::Connected;

            // Enable live_streaming on this socket
            let status_id = match protocols
                .message_pickup
                .toggle_live_delivery(&atm, &self.profile, true)
                .await
            {
                Ok(status_id) => {
                    debug!("Live streaming enabled");
                    status_id
                }
                Err(e) => {
                    error!("Error enabling live streaming: {:?}", e);
                    return;
                }
            };

            let a = self
                .to_handler
                .send(WsConnectionCommands::Connected(self.profile.clone(), status_id))
                .await;

            debug!("Signaled handler that connection is ready: {:?}", a);

            loop {
                select! {
                    value = web_socket.next() => {
                                    if let Some(msg) = value {
                                        if let Ok(payload) = msg {
                                            if payload.is_text() {
                                                if let Ok(msg) = payload.to_text() {
                                                    debug!("Received text message ({})", msg);
                                                    let unpack = match atm.unpack(msg).await {
                                                        Ok(unpack) => unpack,
                                                        Err(e) => {
                                                            error!("Error unpacking message: {:?}", e);
                                                            continue;
                                                        }
                                                    };
                                                    let _ = self.to_handler.send(WsConnectionCommands::MessageReceived(Box::new(unpack))).await;
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
                    value = self.from_handler.recv() => {
                        if let Some(cmd) = value {
                            match cmd {
                                WsConnectionCommands::Send(msg) => {
                                    debug!("Sending message ({}) to websocket", msg);
                                    match web_socket.send(Message::Text(msg)).await {
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
                                _ => {}
                            }
                        }
                    }
                }
            }
            let _ = web_socket.close(None).await;
            debug!("Websocket connection closed");
        }
        .instrument(_span)
        .await;

        Ok(())
    }

    /// Responsible for creating a websocket connection to the mediator
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
        let ws_stream = connect_async_tls_with_config(
            request,
            None,
            false,
            Some(self.shared.ws_connector.clone()),
        )
        .await
        .expect("Failed to connect")
        .0;

        debug!("Completed websocket connection");

        Ok(ws_stream)
    }
}
