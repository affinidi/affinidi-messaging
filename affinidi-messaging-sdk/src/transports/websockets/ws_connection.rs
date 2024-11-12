/*!
A per Profile WebSocket connection to a DIDComm Mediator.
*/
use std::sync::Arc;

use super::{ws_handler::WsHandlerCommands, SharedState};
use crate::{errors::ATMError, profiles::Profile};
use http::header::AUTHORIZATION;
use tokio::{
    net::TcpStream,
    select,
    sync::{
        mpsc::{Receiver, Sender},
        RwLock,
    },
    task::JoinHandle,
};
use tokio_stream::StreamExt;
use tokio_tungstenite::{
    connect_async_tls_with_config, tungstenite::client::IntoClientRequest, MaybeTlsStream,
    WebSocketStream,
};
use tracing::{debug, error};

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
    profile: Arc<RwLock<Profile>>,
    shared: Arc<SharedState>,
    state: State,
    url: String,
    from_handler: Receiver<WsConnectionCommands>,
    to_handler: Sender<WsHandlerCommands>,
}

impl WsConnection {
    pub(crate) async fn activate(
        shared_state: Arc<SharedState>,
        profile: &Arc<RwLock<Profile>>,
        to_handler: Sender<WsHandlerCommands>,
        from_handler: Receiver<WsConnectionCommands>,
    ) -> Result<JoinHandle<()>, ATMError> {
        let profile_alias = profile.read().await.alias.clone();

        let Some(mediator) = &profile.read().await.mediator else {
            return Err(ATMError::ConfigError(format!(
                "Profile ({}) is missing a valid mediator configuration!",
                profile_alias
            )));
        };

        let Some(url) = &mediator.websocket_endpoint else {
            return Err(ATMError::ConfigError(format!(
                "Profile ({}) is missing a valid websocket endpoint!",
                profile_alias
            )));
        };

        let mut connection = WsConnection {
            profile: profile.clone(),
            shared: shared_state.clone(),
            state: State::Disconnected,
            url: url.to_string(),
            from_handler,
            to_handler,
        };
        debug!(
            "Activating websocket connection for profile ({})",
            profile_alias
        );

        let handle = tokio::spawn(async move {
            let _ = connection.run().await;
        });

        Ok(handle)
    }

    async fn run(&mut self) -> Result<(), ATMError> {
        debug!("Starting websocket connection");
        let mut connected: bool = false;
        let mut web_socket = self._create_socket().await?;
        // TODO: Need to implement a recovery here
        debug!("Websocket connected");

        self.to_handler
            .send(WsHandlerCommands::Connected(self.profile.clone()))
            .await;

        loop {
            select! {
                value = web_socket.next() => {
                                if let Some(msg) = value {
                                    if let Ok(payload) = msg {
                                        if payload.is_text() {
                                            if let Ok(msg) = payload.to_text() {
                                                debug!("Received text message ({})", msg);
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
                            WsConnectionCommands::Stop => {
                                debug!("Stopping websocket connection");
                                break;
                            }
                            WsConnectionCommands::Send(msg) => {
                                debug!("Sending message ({}) to websocket", msg);
                                // Send the message to the websocket
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Responsible for creating a websocket connection to the mediator
    async fn _create_socket(
        &mut self,
    ) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>, ATMError> {
        // Check if authenticated
        let tokens = {
            let mut _profile = self.profile.write().await;
            let tokens = _profile.authenticate(&self.shared).await?;

            tokens
        };

        debug!("Creating websocket connection");
        // Create a custom websocket request, turn this into a client_request
        // Allows adding custom headers later

        let _profile = self.profile.read().await;
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
            Some(self.shared.ws_connector.clone()),
        )
        .await
        .expect("Failed to connect")
        .0;

        debug!("Completed websocket connection");

        Ok(ws_stream)
    }
}
